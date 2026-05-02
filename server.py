from filelock import FileLock
import os
import json
import hashlib
import secrets
import uuid as uuid_lib
from fastapi import FastAPI,HTTPException,Request,Body,Header
from fastapi.responses import FileResponse, Response
from slowapi import Limiter
from slowapi.middleware import SlowAPIMiddleware
import sqlite3
import uvicorn
from fastapi.staticfiles import StaticFiles
from PIL import Image, ImageDraw, ImageFont
import random
import io
import redis

UTF = 'utf-8'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ===== Redis Connection =====
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_DB = int(os.environ.get("REDIS_DB", "0"))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)

redis_client = None

def get_redis():
    """延迟连接Redis，避免启动时阻塞"""
    global redis_client
    if redis_client is not None:
        return redis_client
    try:
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=REDIS_PASSWORD,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3
        )
        redis_client.ping()
        return redis_client
    except Exception:
        return None

# ===== Captcha System =====
CAPTCHA_PREFIX = "captcha:"
CAPTCHA_TTL = 60  # 验证码1分钟过期

def generate_arithmetic_captcha(width=180, height=60):
    """生成算术验证码PNG字节流，返回 (bytes, answer)"""
    operators = ['+', '-', '*']
    num1 = random.randint(10, 99)
    num2 = random.randint(1, 99)
    op = random.choice(operators)
    if op == '+':
        answer = num1 + num2
    elif op == '-':
        if num1 < num2:
            num1, num2 = num2, num1
        answer = num1 - num2
    else:
        while num1 * num2 > 999:
            num1 = random.randint(10, 99)
            num2 = random.randint(1, 9)
        answer = num1 * num2
    question = f"{num1} {op} {num2} = ?"
    bg = (random.randint(200, 255), random.randint(200, 255), random.randint(200, 255))
    img = Image.new('RGB', (width, height), bg)
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", size=30)
    except Exception:
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 30)
        except Exception:
            font = ImageFont.load_default()
    for _ in range(600):
        draw.point((random.randint(0, width), random.randint(0, height)),
                   fill=(random.randint(0, 150), random.randint(0, 150), random.randint(0, 150)))
    for _ in range(random.randint(6, 14)):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)],
                  fill=(random.randint(100, 200), random.randint(100, 200), random.randint(100, 200)), width=2)
    tc = (random.randint(0, 80), random.randint(0, 80), random.randint(0, 80))
    bbox = draw.textbbox((0, 0), question, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x, y = (width - tw) // 2 + random.randint(-5, 5), (height - th) // 2 + random.randint(-5, 5)
    draw.text((x, y), question, fill=tc, font=font)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf.getvalue(), str(answer)

# ===== User Auth System =====
def hash_password(password: str, salt: str = None) -> tuple:
    """返回 (hash_hex, salt_hex)"""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 200000)
    return h.hex(), salt

def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    h, _ = hash_password(password, salt)
    return h == stored_hash

# 会话 token -> uuid，存在Redis中，7天过期
SESSION_PREFIX = "session:"
SESSION_TTL = 7 * 24 * 3600  # 7天

def _r():
    """获取Redis连接，无连接返回None"""
    return get_redis()

def get_current_user(request: Request) -> str:
    """从请求头 Authorization 获取当前用户uuid，返回 None 表示未登录"""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        r = _r()
        if r is None:
            return None
        try:
            uid = r.get(f"{SESSION_PREFIX}{token}")
            return uid
        except Exception:
            return None
    return None

def require_user(request: Request) -> str:
    """获取当前用户uuid，未登录则抛出 401"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "请先登录")
    return user

class SQLite:

    def __init__(self):
        self.db_path = './repo/social.db'
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_tables()

    def _get_conn(self) -> sqlite3.Connection:
        """获取数据库连接，开启 WAL 模式提升并发"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # 写不阻塞读
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    
    def _init_tables(self):
        """初始化表结构，不存在就创建，兼容旧表迁移"""
        with self._get_conn() as conn:
            # 检查是否需要迁移：旧users表没有uuid列
            need_migrate = False
            users_cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
            if users_cols and 'uuid' not in users_cols:
                need_migrate = True  # 旧表存在但没有uuid列，需要迁移
            
            if need_migrate:
                # 备份旧表后删除
                conn.executescript("""
                    DROP TABLE IF EXISTS users_old;
                    ALTER TABLE users RENAME TO users_old;
                    DROP TABLE IF EXISTS like_ips;
                    DROP TABLE IF EXISTS comments;
                    DROP TABLE IF EXISTS likes;
                """)
            
            conn.executescript(
"""
CREATE TABLE IF NOT EXISTS users(
    uuid          TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    avatar        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS likes(
    repo_id INTEGER PRIMARY KEY,
    count   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS like_ips(
    user_uuid TEXT NOT NULL,
    repo_id   INTEGER NOT NULL,
    PRIMARY KEY (user_uuid, repo_id)
);

CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id    INTEGER NOT NULL,
    content    TEXT NOT NULL,
    reply      INTEGER,
    user_uuid  TEXT NOT NULL DEFAULT 'anonymous'
);
""")
            # 确保comments有user_uuid列（兼容旧库）
            try:
                cols = [row[1] for row in conn.execute("PRAGMA table_info(comments)").fetchall()]
                if 'user_uuid' not in cols and 'username' in cols:
                    conn.execute("ALTER TABLE comments RENAME COLUMN username TO user_uuid")
                elif 'user_uuid' not in cols:
                    conn.execute("ALTER TABLE comments ADD COLUMN user_uuid TEXT NOT NULL DEFAULT 'anonymous'")
            except Exception:
                pass
            
            # 确保like_ips有user_uuid列
            try:
                like_cols = [row[1] for row in conn.execute("PRAGMA table_info(like_ips)").fetchall()]
                if 'user_uuid' not in like_cols and 'ip' in like_cols:
                    conn.execute("ALTER TABLE like_ips RENAME COLUMN ip TO user_uuid")
                elif 'user_uuid' not in like_cols:
                    conn.execute("ALTER TABLE like_ips ADD COLUMN user_uuid TEXT NOT NULL DEFAULT ''")
            except Exception:
                pass

    def get_username(self, uuid: str) -> str:
        """通过uuid获取用户名"""
        if not uuid or uuid == 'anonymous':
            return 'anonymous'
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT username FROM users WHERE uuid = ?", (uuid,)
            ).fetchone()
            return row['username'] if row else 'anonymous'

    def get_usernames_batch(self, uuids: list) -> dict:
        """批量获取 uuid->username 映射"""
        result = {}
        if not uuids:
            return result
        valid = [u for u in uuids if u and u != 'anonymous']
        if not valid:
            return result
        with self._get_conn() as conn:
            placeholders = ','.join('?' * len(valid))
            rows = conn.execute(
                f"SELECT uuid, username FROM users WHERE uuid IN ({placeholders})",
                valid
            ).fetchall()
            for row in rows:
                result[row['uuid']] = row['username']
        return result

    def like(self, repo_id: int, user_uuid: str) -> bool:
        """点赞，返回 True 表示成功，False 表示该用户已点过"""
        with self._get_conn() as conn:
            try:
                existing = conn.execute(
                    "SELECT 1 FROM like_ips WHERE user_uuid = ? AND repo_id = ?",
                    (user_uuid, repo_id)
                ).fetchone()
                if existing:
                    return False
                conn.execute(
                    "INSERT INTO like_ips(user_uuid, repo_id) VALUES(?, ?)",
                    (user_uuid, repo_id)
                )
                conn.execute(
                    "INSERT INTO likes(repo_id, count) VALUES(?, 1) "
                    "ON CONFLICT(repo_id) DO UPDATE SET count = count + 1",
                    (repo_id,)
                )
                return True
            except Exception:
                return False

    def has_liked(self, repo_id: int, user_uuid: str) -> bool:
        """检查某用户是否已点赞该仓库"""
        if not user_uuid:
            return False
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM like_ips WHERE user_uuid = ? AND repo_id = ?",
                (user_uuid, repo_id)
            ).fetchone()
            return row is not None

    def comment(self, repo_id:int, content:str, reply:int = None, user_uuid:str = 'anonymous') -> None:
        with self._get_conn() as conn:
            if reply is not None:
                conn.execute(
                    "INSERT INTO comments(repo_id, reply, content, user_uuid) VALUES(?, ?, ?, ?)",
                    (repo_id, reply, content, user_uuid)
                )
            else:
                conn.execute(
                    "INSERT INTO comments(repo_id, content, user_uuid) VALUES(?, ?, ?)",
                    (repo_id, content, user_uuid)
                )

    def get_likes(self, repo_id: int) -> int:
        """获取指定仓库的点赞数，若无记录返回 0"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT count FROM likes WHERE repo_id = ?", (repo_id,)
            ).fetchone()
            return row['count'] if row else 0

    def register_user(self, username: str, password: str) -> str:
        """注册用户，返回uuid；用户名已存在返回None"""
        with self._get_conn() as conn:
            try:
                uid = uuid_lib.uuid4().hex
                h, salt = hash_password(password)
                conn.execute(
                    "INSERT INTO users(uuid, username, password_hash, salt) VALUES(?, ?, ?, ?)",
                    (uid, username, h, salt)
                )
                return uid
            except sqlite3.IntegrityError:
                return None

    def get_avatar(self, username: str) -> str:
        """通过用户名获取头像URL，无则返回空字符串"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT avatar FROM users WHERE username = ?", (username,)
            ).fetchone()
            return row['avatar'] if row else ''

    def get_avatar_by_uuid(self, user_uuid: str) -> str:
        """通过uuid获取头像URL"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT avatar FROM users WHERE uuid = ?", (user_uuid,)
            ).fetchone()
            return row['avatar'] if row else ''

    def set_avatar(self, user_uuid: str, avatar_url: str) -> None:
        """通过uuid设置用户头像URL"""
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE users SET avatar = ? WHERE uuid = ?",
                (avatar_url, user_uuid)
            )

    def get_user_avatars(self, usernames: list) -> dict:
        """批量获取用户头像（通过用户名），返回 {username: avatar_url}"""
        if not usernames:
            return {}
        with self._get_conn() as conn:
            placeholders = ','.join('?' * len(usernames))
            rows = conn.execute(
                f"SELECT username, avatar FROM users WHERE username IN ({placeholders})",
                usernames
            ).fetchall()
            return {row['username']: row['avatar'] for row in rows}

    def verify_user_login(self, username: str, password: str) -> str:
        """验证登录，成功返回uuid，失败返回None"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT uuid, password_hash, salt FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            if not row:
                return None
            if verify_password(password, row['salt'], row['password_hash']):
                return row['uuid']
            return None

    def get_comments(self, repo_id: int) -> list:
        """获取评论，只有顶层评论的回复才嵌套，深层回复扁平化并附带mention提示"""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT c.id, c.repo_id, c.content, c.reply, c.user_uuid, "
                "COALESCE(u.username, 'anonymous') as username "
                "FROM comments c LEFT JOIN users u ON c.user_uuid = u.uuid "
                "WHERE c.repo_id = ? ORDER BY c.id",
                (repo_id,)
            ).fetchall()

        # 构建完整结构的临时列表
        comment_map = {}
        for row in rows:
            comment_map[row['id']] = {
                'id': row['id'],
                'reply': row['reply'],
                'content': row['content'],
                'username': row['username'],
                'replies': []
            }

        top = []
        for c in comment_map.values():
            if c['reply'] is None:
                top.append(c)
            else:
                parent = comment_map.get(c['reply'])
                if parent is None:
                    # 孤儿评论，当作顶层
                    top.append(c)
                elif parent['reply'] is None:
                    # 父评论是顶层 → 直接嵌套
                    parent['replies'].append(c)
                else:
                    # 父评论本身也是回复 → 扁平化，附带mention
                    c['mention'] = f"{c['username']} 回复 {parent['username']}"
                    # 找到顶层祖先
                    ancestor = parent
                    while ancestor.get('reply') is not None:
                        anc = comment_map.get(ancestor['reply'])
                        if anc is None:
                            break
                        ancestor = anc
                    if ancestor.get('reply') is None:
                        # 找到了顶层祖先
                        ancestor['replies'].append(c)
                    else:
                        # 没有顶层祖先（数据异常），直接放顶层
                        top.append(c)

        # 清理输出，去除内部字段
        def clean(comment_list):
            cleaned = []
            for c in comment_list:
                item = {
                    'id': c['id'],
                    'content': c['content'],
                    'username': c['username'],
                    'replies': clean(c.get('replies', []))
                }
                if c.get('mention'):
                    item['mention'] = c['mention']
                cleaned.append(item)
            return cleaned

        return clean(top)

class FileEdit:

    def __init__(self, sqlite:SQLite):
        self.root = './repo'
        self.sqlite = sqlite
        
    def new_repository(self, id:int, name:str, user_uuid:str) -> None:
        os.makedirs(f'{self.root}/{id}', exist_ok=True)
        with FileLock(f'{self.root}/{id}/proj.json.lock'):
            with open(f'{self.root}/{id}/proj.json','w',encoding='utf-8') as file:
                json.dump({'files':[],'name':f'{name}','user_uuid':user_uuid},file,ensure_ascii=False)

    def read_repository(self, id:int, user_uuid:str = None) -> dict:
        with FileLock(f'{self.root}/{id}/proj.json.lock'):
            with open(f'{self.root}/{id}/proj.json','r',encoding='utf-8') as file:
                data = json.load(file)
                data['likes'] = self.sqlite.get_likes(id)
                data['comments'] = self.sqlite.get_comments(id)
                # 解析 uuid 为用户名
                owner_uuid = data.get('user_uuid', data.get('user', ''))
                data['user_uuid'] = owner_uuid
                data['user'] = self.sqlite.get_username(owner_uuid) if owner_uuid else 'anonymous'
                if user_uuid:
                    data['has_liked'] = self.sqlite.has_liked(id, user_uuid)
                # 构建文件树
                data['tree'] = self._build_tree(data.get('files', []))
                return data

    def _build_tree(self, files: list) -> dict:
        """将扁平文件列表构建成嵌套树结构（最多3层）
        返回格式: { 'folder': { 'subfolder': { 'file.py': None } }, 'root_file.py': None }
        None 表示文件，dict 表示文件夹
        以 '/' 结尾的条目是空文件夹（例如 'src/'）
        """
        tree = {}
        for f in sorted(files):
            # 判断是否为空文件夹（以 '/' 结尾）
            if f.endswith('/'):
                parts = [p for p in f.split('/') if p]
                current = tree
                for i, part in enumerate(parts):
                    if part not in current:
                        current[part] = {}
                    current = current[part]
            else:
                parts = f.split('/')
                current = tree
                for i, part in enumerate(parts):
                    if i == len(parts) - 1:
                        # 最终文件：用 None 标记
                        current[part] = None
                    else:
                        # 文件夹
                        if part not in current:
                            current[part] = {}
                        current = current[part]
        return tree
    
    def find_repo_id_by_name(self, username: str, reponame: str) -> int:
        """通过用户名+仓库名查找仓库ID，找不到返回None"""
        with FileLock('./repo/all.json.lock'):
            with open('./repo/all.json', 'r', encoding='utf-8') as file:
                content = json.load(file)
        repos = content.get('repos', [])
        for repo in repos:
            try:
                data = self.read_repository(repo['id'])
                repo_user = data.get('user', 'anonymous')
                if repo_user == username and repo['name'] == reponame:
                    return repo['id']
            except Exception:
                pass
        return None
            
    def _validate_path(self, file_name: str) -> str:
        """验证路径深度不超过3层（根目录算第0层）。返回规范化后的路径，非法则抛出ValueError"""
        # 规范化路径：移除开头/结尾斜杠，用/统一分隔
        cleaned = file_name.replace('\\', '/').strip('/')
        # 禁止 .. 路径遍历
        parts = [p for p in cleaned.split('/') if p and p != '.']
        if '..' in parts or '' in [p for p in cleaned.split('/') if p == '']:
            raise ValueError("非法路径")
        if len(parts) == 0:
            raise ValueError("路径不能为空")
        depth = len(parts)  # parts层数: 如 a/b/c 就是3层
        if depth > 3:
            raise ValueError("文件夹嵌套不能超过3层")
        return '/'.join(parts)

    def create_folder(self, id:int, folder_name:str) -> None:
        """创建空文件夹，文件夹名以'/'结尾存入files列表（如 'src/'）"""
        folder_name = self._validate_path(folder_name)
        if folder_name in ('proj.json', 'proj.json/'):
            raise ValueError("不能操作proj.json")
        folder_name = folder_name.strip('/')
        folder_name = folder_name + '/'
        # 确保目录存在
        dir_path = f'{self.root}/{id}/{folder_name}'
        os.makedirs(dir_path, exist_ok=True)
        with FileLock(f'{self.root}/{id}/proj.json.lock'):
            with open(f'{self.root}/{id}/proj.json','r+',encoding='utf-8') as file:
                content = json.load(file)
                if folder_name not in content['files']:
                    content['files'].append(folder_name)
                file.seek(0)
                json.dump(content,file,ensure_ascii=False)
                file.truncate()

    def delete_folder(self, id:int, folder_name:str) -> None:
        """删除文件夹及其内部所有文件/子文件夹"""
        folder_name = self._validate_path(folder_name)
        folder_name = folder_name.strip('/')
        if folder_name in ('proj.json',):
            raise ValueError("不能删除proj.json")
        if not folder_name:
            raise ValueError("路径不能为空")
        prefix = folder_name + '/'
        folder_prefix_on_disk = f'{self.root}/{id}/{prefix}'
        
        # 从文件列表中移除所有属于该文件夹的条目
        with FileLock(f'{self.root}/{id}/proj.json.lock'):
            with open(f'{self.root}/{id}/proj.json','r+',encoding='utf-8') as file:
                content = json.load(file)
                to_delete = []
                for f in content['files']:
                    fn = f.strip('/') + '/' if not f.endswith('/') else f
                    if fn == folder_name + '/' or fn.startswith(prefix):
                        to_delete.append(f)
                for f in to_delete:
                    content['files'].remove(f)
                    # 删除磁盘上的文件/文件夹
                    disk_path = f'{self.root}/{id}/{f}'
                    disk_lock = f'{self.root}/{id}/{f}.lock'
                    with FileLock(disk_lock):
                        if os.path.isdir(disk_path):
                            import shutil
                            shutil.rmtree(disk_path)
                        elif os.path.isfile(disk_path):
                            os.remove(disk_path)
                        # 清理空锁文件
                        if os.path.exists(disk_lock):
                            try:
                                os.remove(disk_lock)
                            except Exception:
                                pass
                # 清理该文件夹目录本身
                folder_path = f'{self.root}/{id}/{folder_name}'
                if os.path.isdir(folder_path):
                    try:
                        os.rmdir(folder_path)
                    except OSError:
                        pass
                file.seek(0)
                json.dump(content,file,ensure_ascii=False)
                file.truncate()

    def write_file(self, id:int, file_name:str, data:str) -> None:
        file_name = self._validate_path(file_name)
        if file_name == 'proj.json':
            file_name = 'proj_.json'
        # 确保目录存在
        file_dir = os.path.dirname(f'{self.root}/{id}/{file_name}')
        if file_dir:
            os.makedirs(file_dir, exist_ok=True)
        with FileLock(f'{self.root}/{id}/{file_name}.lock'):
            with open(f'{self.root}/{id}/{file_name}','w',encoding='utf-8') as file:
                file.write(data)
            with FileLock(f'{self.root}/{id}/proj.json.lock'):
                with open(f'{self.root}/{id}/proj.json','r+',encoding='utf-8') as file:
                    content = json.load(file)
                    if file_name not in content['files']:
                        content['files'].append(file_name)
                    file.seek(0)
                    json.dump(content,file,ensure_ascii=False)
                    file.truncate()

    def delete_file(self, id:int, file_name:str) -> None:
        """删除仓库中的文件，proj.json不可删除"""
        file_name = self._validate_path(file_name)
        if file_name in ('proj.json',):
            raise ValueError("不能删除proj.json")
        file_path = f'{self.root}/{id}/{file_name}'
        lock_path = f'{self.root}/{id}/{file_name}.lock'
        # 移除文件
        with FileLock(lock_path):
            if os.path.exists(file_path):
                os.remove(file_path)
            # 尝试删除空目录
            file_dir = os.path.dirname(file_path)
            if file_dir and os.path.isdir(file_dir):
                try:
                    if not os.listdir(file_dir):
                        os.rmdir(file_dir)
                except OSError:
                    pass
        # 从文件列表中移除
        with FileLock(f'{self.root}/{id}/proj.json.lock'):
            with open(f'{self.root}/{id}/proj.json','r+',encoding='utf-8') as file:
                content = json.load(file)
                if file_name in content['files']:
                    content['files'].remove(file_name)
                file.seek(0)
                json.dump(content,file,ensure_ascii=False)
                file.truncate()

    def read_file(self, id:int, file_name:str) -> str:
        file_name = self._validate_path(file_name)
        with FileLock(f'{self.root}/{id}/{file_name}.lock'):
            with open(f'{self.root}/{id}/{file_name}','r',encoding='utf-8') as file:
                data = file.read()
                return data
            
def hash_ip(ip: str) -> str:
    return hashlib.sha256(ip.encode('utf-8')).hexdigest()
            
def get_real_ip(request: Request) -> str:
    """
    获取真实 IP（仅用于速率限制，不作为身份标识）
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return hash_ip(forwarded.split(",")[0].strip())
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return hash_ip(real_ip.strip())
    if request.client:
        return hash_ip(request.client.host)
    return "unknown"

def get_repo_id_sort() -> int:
    try:
        with FileLock('./repo/all.json.lock'):
            with open('./repo/all.json','r',encoding=UTF) as file:
                content:dict = json.load(file)
                return content.get('repos',[])[-1].get('id',0)
    except FileNotFoundError:
        with FileLock('./repo/all.json.lock'):
            with open('./repo/all.json','w',encoding=UTF) as file:
                json.dump({'repos':[]},file,ensure_ascii=False)
        return 0
    except IndexError:
        return 0
    except Exception as e:
        print(f'Error:{e}')
        return 0
            
app = FastAPI()
limiter = Limiter(key_func=get_real_ip)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

sqlite = SQLite()
fileedit = FileEdit(sqlite)
repo_id = get_repo_id_sort() + 1

MAX_UPLOAD_SIZE = 100 * 1024

def add_repo(data:dict, id:int) -> bool:
    try:
        with FileLock('./repo/all.json.lock'):
            with open('./repo/all.json','r+',encoding=UTF) as file:
                file.seek(0)
                content = json.load(file)
                content['repos'].append({"name":data.get('name','unknow'),'id':id})
                file.seek(0)
                json.dump(content,file,ensure_ascii=False)
                file.truncate()
                return True
    except FileNotFoundError:
        with FileLock('./repo/all.json.lock'):
            with open('./repo/all.json','w',encoding=UTF) as file:
                json.dump({"repos":[{"name":data.get('name','unknow'),'id':id}]},file,ensure_ascii=False)
                return True
    except Exception as e:
        print(f"Error:{e}")
        return False

@app.middleware("http")
async def limit_upload_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        length = int(content_length)
        if length > MAX_UPLOAD_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"请求体过大，最大允许 {MAX_UPLOAD_SIZE // 1024}kb"
            )
    response = await call_next(request)
    return response

# ===== Auth APIs =====
@app.get('/api/auth/captcha')
async def get_captcha():
    """生成验证码图片，返回PNG字节流。captcha_token和答案存储在captcha_store中"""
    captcha_token = secrets.token_hex(16)
    img_bytes, answer = generate_arithmetic_captcha()
    r = _r()
    if r is not None:
        try:
            r.setex(f"{CAPTCHA_PREFIX}{captcha_token}", CAPTCHA_TTL, answer)
        except Exception:
            pass
    return Response(content=img_bytes, media_type="image/png",
                    headers={"X-Captcha-Token": captcha_token})

def verify_captcha(captcha_token: str, captcha_input: str) -> bool:
    """验证验证码答案，验证后删除token（一次性使用）"""
    if not captcha_token or not captcha_input:
        return False
    r = _r()
    if r is None:
        return False
    try:
        expected = r.get(f"{CAPTCHA_PREFIX}{captcha_token}")
        if expected is None:
            return False
        r.delete(f"{CAPTCHA_PREFIX}{captcha_token}")
        return captcha_input.strip() == expected
    except Exception:
        return False

@app.post('/api/auth/register')
async def auth_register(data: dict = Body(...)):
    try:
        username = data.get('username', '').strip()
        password = data.get('password', '')
        captcha_token = data.get('captcha_token', '')
        captcha_input = data.get('captcha', '').strip()
        if not username or not password:
            raise HTTPException(400, "用户名和密码不能为空")
        if not captcha_input:
            raise HTTPException(400, "请输入验证码")
        if not verify_captcha(captcha_token, captcha_input):
            raise HTTPException(400, "验证码错误或已过期，请刷新重试")
        if len(username) > 50:
            raise HTTPException(400, "用户名不能超过50字符")
        if len(password) < 4:
            raise HTTPException(400, "密码不能少于4位")
        uid = sqlite.register_user(username, password)
        if uid is None:
            raise HTTPException(409, "用户名已存在")
        # 注册成功自动登录
        token = secrets.token_hex(32)
        r = _r()
        if r is not None:
            try:
                r.setex(f"{SESSION_PREFIX}{token}", SESSION_TTL, uid)
            except Exception:
                pass
        avatar = sqlite.get_avatar_by_uuid(uid)
        return {"token": token, "username": username, "avatar": avatar}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error:{e}")
        raise HTTPException(500, "注册失败")

@app.post('/api/auth/login')
async def auth_login(data: dict = Body(...)):
    try:
        username = data.get('username', '').strip()
        password = data.get('password', '')
        captcha_token = data.get('captcha_token', '')
        captcha_input = data.get('captcha', '').strip()
        if not username or not password:
            raise HTTPException(400, "用户名和密码不能为空")
        if not captcha_input:
            raise HTTPException(400, "请输入验证码")
        if not verify_captcha(captcha_token, captcha_input):
            raise HTTPException(400, "验证码错误或已过期，请刷新重试")
        uid = sqlite.verify_user_login(username, password)
        if uid is None:
            raise HTTPException(401, "用户名或密码错误")
        token = secrets.token_hex(32)
        r = _r()
        if r is not None:
            try:
                r.setex(f"{SESSION_PREFIX}{token}", SESSION_TTL, uid)
            except Exception:
                pass
        avatar = sqlite.get_avatar_by_uuid(uid)
        return {"token": token, "username": username, "avatar": avatar}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error:{e}")
        raise HTTPException(500, "登录失败")

@app.post('/api/auth/logout')
async def auth_logout(request: Request):
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        r = _r()
        if r is not None:
            try:
                r.delete(f"{SESSION_PREFIX}{token}")
            except Exception:
                pass
    return {"ok": True}

@app.get('/api/auth/me')
async def auth_me(request: Request):
    uid = get_current_user(request)
    if uid:
        username = sqlite.get_username(uid)
        avatar = sqlite.get_avatar_by_uuid(uid)
        return {"username": username, "avatar": avatar}
    return {"username": None, "avatar": ""}

@app.post('/api/auth/avatar')
@limiter.limit("5/minute")
async def set_avatar(request: Request, data: dict = Body(...)):
    try:
        uid = require_user(request)
        url = data.get('avatar', '').strip()
        if len(url) > 1000:
            raise HTTPException(400, "URL过长")
        sqlite.set_avatar(uid, url)
        return {"ok": True, "avatar": url}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error:{e}")
        raise HTTPException(500, "设置头像失败")

@app.get('/api/avatars')
async def get_avatars(usernames: str = ""):
    """批量获取用户头像，参数: ?usernames=user1,user2"""
    try:
        names = [n.strip() for n in usernames.split(',') if n.strip()]
        if not names:
            return {}
        return sqlite.get_user_avatars(names)
    except Exception as e:
        print(f"Error:{e}")
        return {}

@app.get('/api/repo/by-name/{username}/{reponame:path}')
@limiter.limit("20/minute")
async def get_repo_by_name(username: str, reponame: str, request: Request):
    """通过用户名+仓库名直接获取仓库信息"""
    try:
        uid = get_current_user(request)
        rid = fileedit.find_repo_id_by_name(username, reponame)
        if rid is None:
            raise HTTPException(404, '仓库不存在')
        repo = fileedit.read_repository(int(rid), uid)
        repo['id'] = rid
        repo['name'] = reponame
        return repo
    except HTTPException:
        raise
    except FileNotFoundError:
        raise HTTPException(404, '仓库不存在或已损坏')
    except Exception as e:
        print(f'Error:{e}')
        raise HTTPException(500, "获取失败")

@app.get('/api/repo/{id}/isown')
@limiter.limit("20/minute")
async def get_isown(id:int, request:Request) -> dict:
    try:
        uid = get_current_user(request)
        data = fileedit.read_repository(int(id))
        return {'is': True if data.get('user_uuid') == uid else False}
    except FileNotFoundError:
        raise HTTPException(404,'仓库不存在或已损坏')
    except Exception as e:
        print(f'Error:{e}')
        raise HTTPException(500,"获取失败")
            
@app.get('/api/repo/mine')
@limiter.limit("10/minute")
async def get_my_repos(request: Request):
    """获取当前用户自己的仓库列表"""
    try:
        uid = require_user(request)
        with FileLock('./repo/all.json.lock'):
            with open('./repo/all.json', 'r', encoding=UTF) as file:
                content = json.load(file)
        repos = content.get('repos', [])
        my_repos = []
        for repo in repos:
            try:
                data = fileedit.read_repository(repo['id'])
                if data.get('user_uuid') == uid:
                    my_repos.append({
                        'id': repo['id'],
                        'name': repo['name'],
                        'likes': data.get('likes', 0),
                        'files': len(data.get('files', []))
                    })
            except Exception:
                pass
        username = sqlite.get_username(uid)
        return {"repos": my_repos, "username": username}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error:{e}")
        raise HTTPException(500, "获取我的仓库失败")

@app.get('/api/repo/{id}')
@limiter.limit("20/minute")
async def get_repo(id:int, request:Request) -> dict:
    try:
        if id == -1:
            with FileLock('./repo/all.json.lock'):
                with open('./repo/all.json','r',encoding=UTF) as file:
                    content:dict = json.load(file)
                    for repo in content.get('repos', []):
                        repo['likes'] = sqlite.get_likes(repo['id'])
                    return content
        uid = get_current_user(request)
        repo = fileedit.read_repository(int(id), uid)
        return repo
    except FileNotFoundError:
        raise HTTPException(404,'仓库不存在或已损坏')
    except Exception as e:
        print(f'Error:{e}')
        raise HTTPException(500 ,"获取失败")

@app.get('/api/file/{id}/{file:path}')
@limiter.limit("10/minute")
async def get_code(id:int, file:str, request:Request) -> dict:
    try:
        code = fileedit.read_file(int(id), file)
        return {'code':code}
    except FileNotFoundError:
        raise HTTPException(404,'文件不存在')
    except Exception as e:
        print(f'Error:{e}')
        raise HTTPException(500,"获取失败")

@app.delete('/api/file/{id}')
@limiter.limit("20/minute")
async def delete_file_route(id:int, data:dict = Body(...), request:Request = None):
    """删除仓库中的文件"""
    try:
        uid = require_user(request)
        repo = fileedit.read_repository(int(id))
        if repo.get('user_uuid') != uid:
            raise HTTPException(403, '无法修改他人仓库文件')
        file_name = data.get('name', '')
        if not file_name:
            raise HTTPException(400, "参数错误：缺少文件名")
        fileedit.delete_file(int(id), file_name)
        return {"ok": True}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except HTTPException:
        raise
    except FileNotFoundError:
        raise HTTPException(404, '文件不存在')
    except Exception as e:
        print(f'Error:{e}')
        raise HTTPException(500, '删除失败')

@app.post('/api/post/repo')
@limiter.limit("1/minute")
async def post_repo(data:dict = Body(...), request:Request = None) -> dict:
    try:
        global repo_id
        uid = require_user(request)
        fileedit.new_repository(repo_id, data.get('name','unknow'), uid)
        add_true = add_repo(data, repo_id)
        if add_true:
            repo_id += 1
            return {'id': repo_id-1}
        else:
            raise HTTPException(500, '创建仓库可能已损坏')
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error:{e}")
        raise HTTPException(500, '创建仓库失败')
    
@app.post('/api/post/folder')
@limiter.limit("10/minute")
async def post_folder(data:dict = Body(...), request:Request = None):
    try:
        uid = require_user(request)
        id = data['id']
        if fileedit.read_repository(id).get('user_uuid','--') == uid:
            fileedit.create_folder(id, data.get('name','unknow'))
            return {"ok": True}
        else:
            raise HTTPException(403, '无法修改他人仓库')
    except KeyError:
        raise HTTPException(400, "参数错误")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except HTTPException:
        raise
    except Exception as e:
        print(f'Error:{e}')
        raise HTTPException(500,'创建文件夹失败')

@app.delete('/api/folder/{id}')
@limiter.limit("10/minute")
async def delete_folder_route(id:int, data:dict = Body(...), request:Request = None):
    """删除仓库中的文件夹"""
    try:
        uid = require_user(request)
        repo = fileedit.read_repository(int(id))
        if repo.get('user_uuid') != uid:
            raise HTTPException(403, '无法修改他人仓库')
        folder_name = data.get('name', '')
        if not folder_name:
            raise HTTPException(400, "参数错误：缺少文件夹名")
        fileedit.delete_folder(int(id), folder_name)
        return {"ok": True}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except HTTPException:
        raise
    except FileNotFoundError:
        raise HTTPException(404, '文件夹不存在')
    except Exception as e:
        print(f'Error:{e}')
        raise HTTPException(500, '删除文件夹失败')

@app.post('/api/post/file')
@limiter.limit("5/minute")
async def post_file(data:dict = Body(...), request:Request = None) -> None:
    try:
        uid = require_user(request)
        id = data['id']
        if fileedit.read_repository(id).get('user_uuid','--') == uid:
            fileedit.write_file(id, data.get('name','unknow'), data.get('data','none'))
        else:
            raise HTTPException(403, '无法修改他人仓库文件')
    except KeyError:
        raise HTTPException(400, "参数错误")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except HTTPException:
        raise
    except Exception as e:
        print(f'Error:{e}')
        raise HTTPException(500,'修改失败')
    
@app.post('/api/post/like/{id}')
@limiter.limit("10/minute")
async def like(id:int, request:Request = None):
    try:
        uid = require_user(request)
        success = sqlite.like(int(id), uid)
        if not success:
            raise HTTPException(403, "你已经给这个仓库点过赞了")
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error:{e}")
        raise HTTPException(500,"点赞失败")
    
@app.post('/api/post/comment')
@limiter.limit("2/minute")
async def comment(body:dict = Body(...), request:Request = None):
    try:
        uid = require_user(request)
        sqlite.comment(body['id'], body['content'], body.get('reply', None), uid)
    except KeyError:
        raise HTTPException(400, "参数错误")
    except Exception as e:
        print(f"Error:{e}")
        raise HTTPException(500,"评论失败")
    
@app.get('/favicon.ico')
async def favicon():
    return ""
            
if __name__ == "__main__":
    app.mount("/", StaticFiles(directory=os.path.join(BASE_DIR, "public"), html=True), name="static")
    uvicorn.run(app, host="0.0.0.0", port=8000)
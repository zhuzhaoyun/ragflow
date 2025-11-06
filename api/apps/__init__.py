#
#  Copyright 2024 The InfiniFlow Authors. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
import os
import sys
import logging
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from flask import Blueprint, Flask, request, jsonify
from werkzeug.wrappers.request import Request
from werkzeug.exceptions import NotFound
from flask_cors import CORS
from flasgger import Swagger
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer

from common.constants import StatusEnum
from api.db.db_models import close_connection
from api.db.services import UserService
from api.utils.json_encode import CustomJSONEncoder
from api.utils import commands

from flask_mail import Mail
from flask_session import Session
from flask_login import LoginManager
from common import settings
from api.utils.api_utils import server_error_response, get_json_result
from common.constants import RetCode
from api.constants import API_VERSION

__all__ = ["app"]

Request.json = property(lambda self: self.get_json(force=True, silent=True))

app = Flask(__name__)


# 延迟导入RuntimeConfig以避免循环导入
def is_debug_mode():
    """检查是否处于DEBUG模式"""
    try:
        from api.db.runtime_config import RuntimeConfig
        return RuntimeConfig.DEBUG if RuntimeConfig.DEBUG is not None else False
    except (ImportError, AttributeError):
        # 如果RuntimeConfig未初始化，通过app.config检查
        return app.config.get('DEBUG', False)
smtp_mail_server = Mail()

# Add this at the beginning of your file to configure Swagger UI
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/apispec.json",
            "rule_filter": lambda rule: True,  # Include all endpoints
            "model_filter": lambda tag: True,  # Include all models
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/",
}

swagger = Swagger(
    app,
    config=swagger_config,
    template={
        "swagger": "2.0",
        "info": {
            "title": "RAGFlow API",
            "description": "",
            "version": "1.0.0",
        },
        "securityDefinitions": {
            "ApiKeyAuth": {"type": "apiKey", "name": "Authorization", "in": "header"}
        },
    },
)

CORS(app, supports_credentials=True, max_age=2592000)
app.url_map.strict_slashes = False
app.json_encoder = CustomJSONEncoder
app.errorhandler(Exception)(server_error_response)


def handle_404_error(e):
    """处理404错误，记录详细的请求信息用于调试"""
    # 记录请求的详细信息
    request_info = {
        "method": request.method,
        "url": request.url,
        "path": request.path,
        "query_string": request.query_string.decode('utf-8') if request.query_string else None,
        "remote_addr": request.remote_addr,
        "headers": dict(request.headers),
        "content_type": request.content_type,
        "content_length": request.content_length,
    }
    
    # 记录请求体（如果有且不是太大的话）
    try:
        if request.content_length and request.content_length < 1024:  # 只记录小于1KB的请求体
            if request.is_json:
                request_info["json_body"] = request.get_json(silent=True)
            elif request.form:
                request_info["form_data"] = dict(request.form)
    except Exception as ex:
        logging.warning(f"Failed to capture request body: {ex}")
    
    # 获取已注册的路由列表（用于分析）
    registered_routes = []
    try:
        for rule in app.url_map.iter_rules():
            registered_routes.append({
                "rule": rule.rule,
                "methods": sorted(rule.methods),
                "endpoint": rule.endpoint
            })
    except Exception as ex:
        logging.warning(f"Failed to get registered routes: {ex}")
    
    # 查找相似的路由（用于提示）
    similar_routes = []
    if request.path:
        for rule in app.url_map.iter_rules():
            # 简单的相似度检查：检查路径前缀或相似部分
            if request.path.startswith(rule.rule.split('<')[0]) or rule.rule.startswith(request.path.split('/')[0]):
                if rule.rule not in [r["rule"] for r in similar_routes]:
                    similar_routes.append({
                        "rule": rule.rule,
                        "methods": sorted(rule.methods),
                        "endpoint": rule.endpoint
                    })
    
    # 记录详细的404错误信息
    logging.error(
        f"404 Not Found - Request details: {request_info}, "
        f"Similar routes: {similar_routes[:5] if similar_routes else 'None'}"
    )
    
    # 如果启用了DEBUG模式，记录所有注册的路由
    if is_debug_mode():
        logging.debug(f"All registered routes ({len(registered_routes)}): {registered_routes}")
    
    # 返回标准的JSON错误响应
    return get_json_result(
        code=RetCode.EXCEPTION_ERROR,
        message=f"The requested URL was not found on the server. Path: {request.path}, Method: {request.method}"
    ), 404


# 注册404错误处理器
app.errorhandler(404)(handle_404_error)
app.errorhandler(NotFound)(handle_404_error)

## convince for dev and debug
# app.config["LOGIN_DISABLED"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["MAX_CONTENT_LENGTH"] = int(
    os.environ.get("MAX_CONTENT_LENGTH", 1024 * 1024 * 1024)
)

Session(app)
login_manager = LoginManager()
login_manager.init_app(app)

commands.register_commands(app)


def search_pages_path(pages_dir):
    app_path_list = [
        path for path in pages_dir.glob("*_app.py") if not path.name.startswith(".")
    ]
    api_path_list = [
        path for path in pages_dir.glob("*sdk/*.py") if not path.name.startswith(".")
    ]
    app_path_list.extend(api_path_list)
    return app_path_list


def register_page(page_path):
    path = f"{page_path}"

    page_name = page_path.stem.removesuffix("_app")
    module_name = ".".join(
        page_path.parts[page_path.parts.index("api"): -1] + (page_name,)
    )

    spec = spec_from_file_location(module_name, page_path)
    page = module_from_spec(spec)
    page.app = app
    page.manager = Blueprint(page_name, module_name)
    sys.modules[module_name] = page
    spec.loader.exec_module(page)
    page_name = getattr(page, "page_name", page_name)
    sdk_path = "\\sdk\\" if sys.platform.startswith("win") else "/sdk/"
    url_prefix = (
        f"/api/{API_VERSION}" if sdk_path in path else f"/{API_VERSION}/{page_name}"
    )

    app.register_blueprint(page.manager, url_prefix=url_prefix)
    
    # 记录注册的路由信息
    registered_routes_count = len(list(app.url_map.iter_rules()))
    logging.debug(f"Registered blueprint '{page_name}' with prefix '{url_prefix}', total routes: {registered_routes_count}")
    
    return url_prefix


pages_dir = [
    Path(__file__).parent,
    Path(__file__).parent.parent / "api" / "apps",
    Path(__file__).parent.parent / "api" / "apps" / "sdk",
]

client_urls_prefix = [
    register_page(path) for dir in pages_dir for path in search_pages_path(dir)
]

# 记录所有注册的路由摘要（仅在启动时记录一次）
def log_registered_routes():
    """记录所有已注册的路由，用于调试"""
    routes_by_prefix = {}
    for rule in app.url_map.iter_rules():
        prefix = rule.rule.split('/')[1] if len(rule.rule.split('/')) > 1 else ''
        if prefix not in routes_by_prefix:
            routes_by_prefix[prefix] = []
        routes_by_prefix[prefix].append({
            "rule": rule.rule,
            "methods": sorted(rule.methods),
            "endpoint": rule.endpoint
        })
    
    logging.info(f"Total registered routes: {len(list(app.url_map.iter_rules()))}")
    if is_debug_mode():
        logging.debug("Registered routes by prefix:")
        for prefix, routes in sorted(routes_by_prefix.items()):
            logging.debug(f"  Prefix '{prefix}': {len(routes)} routes")
            for route in routes[:3]:  # 只显示前3个
                logging.debug(f"    {route['methods']} {route['rule']}")
            if len(routes) > 3:
                logging.debug(f"    ... and {len(routes) - 3} more routes")


# 在路由注册完成后调用，记录所有注册的路由
def log_routes_after_registration():
    """在路由注册完成后调用，记录所有注册的路由"""
    try:
        log_registered_routes()
    except Exception as e:
        logging.warning(f"Failed to log registered routes: {e}")


# 在路由注册完成后调用
log_routes_after_registration()


@login_manager.request_loader
def load_user(web_request):
    jwt = Serializer(secret_key=settings.SECRET_KEY)
    authorization = web_request.headers.get("Authorization")
    if authorization:
        try:
            access_token = str(jwt.loads(authorization))

            if not access_token or not access_token.strip():
                logging.warning("Authentication attempt with empty access token")
                return None

            # Access tokens should be UUIDs (32 hex characters)
            if len(access_token.strip()) < 32:
                logging.warning(f"Authentication attempt with invalid token format: {len(access_token)} chars")
                return None

            user = UserService.query(
                access_token=access_token, status=StatusEnum.VALID.value
            )
            if user:
                if not user[0].access_token or not user[0].access_token.strip():
                    logging.warning(f"User {user[0].email} has empty access_token in database")
                    return None
                return user[0]
            else:
                return None
        except Exception as e:
            logging.warning(f"load_user got exception {e}")
            return None
    else:
        return None


@app.teardown_request
def _db_close(exc):
    close_connection()


@app.before_request
def log_request_info():
    """记录请求信息，用于调试和问题排查"""
    # 记录请求的基本信息
    request_log = {
        "method": request.method,
        "path": request.path,
        "remote_addr": request.remote_addr,
    }
    
    # 在DEBUG模式下记录更详细的信息
    if is_debug_mode():
        request_log.update({
            "url": request.url,
            "query_string": request.query_string.decode('utf-8') if request.query_string else None,
            "content_type": request.content_type,
            "content_length": request.content_length,
            "user_agent": request.headers.get('User-Agent'),
        })
        logging.debug(f"Incoming request: {request_log}")
    else:
        # 非DEBUG模式下只记录关键信息
        logging.info(f"Request: {request.method} {request.path} from {request.remote_addr}")


@app.after_request
def log_response_info(response):
    """记录响应信息，用于调试"""
    if is_debug_mode():
        logging.debug(
            f"Response: {request.method} {request.path} - "
            f"Status: {response.status_code}, "
            f"Content-Type: {response.content_type}, "
            f"Content-Length: {response.content_length}"
        )
    return response

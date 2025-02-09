from flask import Flask, redirect, url_for, session, render_template, flash, request
from authlib.integrations.flask_client import OAuth
from functools import wraps
import yaml
import logging
import sys
import boto3


def load_config(file_path='config.yaml'):
    with open(file_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def setup_logging():
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)

    logger = logging.getLogger('oauth_debug')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(console_handler)

    app.logger.setLevel(logging.DEBUG)
    app.logger.handlers.clear()
    app.logger.addHandler(console_handler)

    return logger


def handle_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.error(f"Error in {f.__name__}: {str(e)}", exc_info=True)
            flash("처리 중 문제가 발생했습니다. 다시 시도해주세요.", "danger")
            return redirect(url_for('index'))
    return decorated_function


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            flash("로그인이 필요합니다.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# 설정 로드
config = load_config('config.yaml')

app = Flask(__name__)
app.secret_key = config['flask']['secret_key']
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600
)

# OAuth 설정 (Cognito User Pool 기반)
oauth = OAuth(app)
oauth.register(
    name='oidc',
    authority=config['cognito']['authority'],
    server_metadata_url=config['cognito']['metadata_url'],
    client_id=config['cognito']['client_id'],
    client_secret=config['cognito']['client_secret'],
    client_kwargs={'scope': 'openid email'}
)

logger = setup_logging()

# AWS 관련 설정 (region 등)
aws_config = config['aws']


def get_temporary_credentials(id_token):
    cognito_identity_client = boto3.client(
        'cognito-identity', region_name=aws_config['region'])
    id_response = cognito_identity_client.get_id(
        IdentityPoolId=config['cognito']['identity_pool_id'],
        Logins={config['cognito']['user_pool_provider_name']: id_token}
    )
    identity_id = id_response['IdentityId']
    creds_response = cognito_identity_client.get_credentials_for_identity(
        IdentityId=identity_id,
        Logins={config['cognito']['user_pool_provider_name']: id_token}
    )
    return creds_response['Credentials']


def get_s3_client(temp_credentials):
    return boto3.client(
        's3',
        region_name=aws_config['region'],
        aws_access_key_id=temp_credentials['AccessKeyId'],
        aws_secret_access_key=temp_credentials['SecretKey'],
        aws_session_token=temp_credentials['SessionToken']
    )


def get_user_s3_client():
    id_token = session.get('id_token')
    if not id_token:
        raise Exception("ID token not found in session")
    temp_credentials = get_temporary_credentials(id_token)
    return get_s3_client(temp_credentials)


@app.route('/')
@handle_errors
def index():
    user = session.get('user')
    return render_template('index.html', user=user)


@app.route('/login')
@handle_errors
def login():
    app.logger.debug('Login process started')
    return oauth.oidc.authorize_redirect('http://localhost:5000/authorize')


@app.route('/authorize')
@handle_errors
def authorize():
    token = oauth.oidc.authorize_access_token()
    app.logger.debug("Received token: %s", token)
    session['user'] = token.get('userinfo')
    session['id_token'] = token.get('id_token')
    return redirect(url_for('index'))


@app.route('/logout')
@handle_errors
def logout():
    session.pop('user', None)
    session.pop('id_token', None)
    return redirect(url_for('index'))

# S3 관련 엔드포인트


@app.route('/buckets')
@login_required
@handle_errors
def list_buckets():
    s3_client = get_user_s3_client()
    response = s3_client.list_buckets()
    buckets = response.get('Buckets', [])
    return render_template('buckets.html', buckets=buckets)


@app.route('/buckets/<bucket_name>/', defaults={'prefix': ''})
@app.route('/buckets/<bucket_name>/<path:prefix>')
@login_required
@handle_errors
def list_objects(bucket_name, prefix):
    s3_client = get_user_s3_client()

    # S3 객체 목록 조회 (폴더와 파일 구분)
    response = s3_client.list_objects_v2(
        Bucket=bucket_name, Prefix=prefix, Delimiter='/')

    # 폴더 목록 가져오기 (디렉토리 구조 유지)
    folders = [prefix['Prefix'] for prefix in response.get(
        'CommonPrefixes', [])] if 'CommonPrefixes' in response else []

    # 파일 목록 가져오기 (폴더가 아닌 파일만)
    objects = [obj for obj in response.get(
        'Contents', []) if obj['Key'] != prefix] if 'Contents' in response else []

    # 부모 폴더 경로 계산 (현재 경로에서 마지막 '/' 이전까지)
    parent_prefix = '/'.join(prefix.rstrip('/').split('/')
                             [:-1]) + '/' if prefix else ''

    return render_template('objects.html',
                           bucket_name=bucket_name,
                           objects=objects,
                           folders=folders,
                           prefix=prefix,
                           parent_prefix=parent_prefix)


@app.route('/buckets/<bucket_name>/upload', methods=['GET', 'POST'])
@login_required
@handle_errors
def upload_file(bucket_name):
    s3_client = get_user_s3_client()

    if request.method == 'POST':
        file_obj = request.files.get('file')
        folder_path = request.form.get('folder_path', '').strip()

        if file_obj:
            object_key = f"{folder_path.rstrip('/')}/{file_obj.filename}" if folder_path else file_obj.filename
            s3_client.upload_fileobj(file_obj, bucket_name, object_key)
            flash(f"{object_key} 업로드 성공", "success")
            return redirect(url_for('list_objects', bucket_name=bucket_name, prefix=folder_path))

        else:
            flash("업로드할 파일이 선택되지 않았습니다.", "warning")

    response = s3_client.list_objects_v2(Bucket=bucket_name, Delimiter='/')
    folders = [prefix['Prefix'] for prefix in response.get(
        'CommonPrefixes', [])] if 'CommonPrefixes' in response else []

    return render_template('upload.html', bucket_name=bucket_name, folders=folders)


@app.route('/buckets/<bucket_name>/create-folder', methods=['POST'])
@login_required
@handle_errors
def create_folder(bucket_name):
    folder_name = request.form.get('new_folder', '').strip()

    if folder_name:
        s3_client = get_user_s3_client()
        folder_key = f"{folder_name.rstrip('/')}/"
        s3_client.put_object(Bucket=bucket_name, Key=folder_key)
        flash(f"Folder '{folder_key}' created successfully", "success")
    else:
        flash("Folder name cannot be empty.", "warning")

    return redirect(url_for('upload_file', bucket_name=bucket_name))


@app.route('/buckets/<bucket_name>/download/<path:object_key>')
@login_required
@handle_errors
def download_file(bucket_name, object_key):
    s3_client = get_user_s3_client()
    filename = object_key.split('/')[-1]
    presigned_url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket_name, 'Key': object_key,
                'ResponseContentDisposition': f'attachment; filename="{filename}"'},
        ExpiresIn=3600
    )
    return redirect(presigned_url)


@app.route('/buckets/<bucket_name>/delete/<path:object_key>', methods=['POST'])
@login_required
@handle_errors
def delete_file(bucket_name, object_key):
    s3_client = get_user_s3_client()
    s3_client.delete_object(Bucket=bucket_name, Key=object_key)
    flash(f"{object_key} 삭제 성공", "success")
    return redirect(url_for('list_objects', bucket_name=bucket_name))


if __name__ == '__main__':
    app.run(debug=True)

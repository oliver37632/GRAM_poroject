import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, VARCHAR, Integer, text, ForeignKey, TIMESTAMP, DATETIME

from flask import Flask, request, abort

from werkzeug.exceptions import NotFound

from config import MYSQL_DB_URL

from werkzeug.security import generate_password_hash, check_password_hash

from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity

from datetime import timedelta

engine = create_engine(MYSQL_DB_URL)

Base = declarative_base()

Session = sessionmaker(bind=engine)
session = Session()

app = Flask(__name__)

jwt = JWTManager(app)


class Post(Base):
    __tablename__ = 'post'

    id = Column(Integer, primary_key=True, autoincrement=True)
    content = Column(VARCHAR(255), nullable=False)
    title = Column(VARCHAR(20), nullable=False)
    created_at = Column(DATETIME, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    user_id = Column(VARCHAR(10), ForeignKey('user.id'))


class User(Base):
    __tablename__ = 'user'

    id = Column(VARCHAR(10), primary_key=True, autoincrement=True, server_default=text("CURRENT_TIMESTAMP"))
    password = Column(VARCHAR(255), nullable=True)
    name = Column(VARCHAR(5), nullable=True)


class Comment(Base):
    __tablename__ = 'comment'

    id = Column(Integer, primary_key=True, autoincrement=True)
    content = Column(VARCHAR(255), nullable=True)
    created_at = Column(DATETIME, nullable=True, )
    post_id = Column(Integer, ForeignKey('post.id'))
    user_id = Column(VARCHAR(10), ForeignKey('user.id'))


@app.route('/signup', methods=['POST'])
def sigup():
    id = request.json['id']
    name = request.json['name']
    password = request.json['password']

    new_sigup = User(
        id=id,
        name=name,
        password=generate_password_hash(password)
    )

    session.add(new_sigup)
    session.commit()

    return {
               "message": "ssuccess"
           }, 200


@app.route('/auth', methods=['POST'])
def auth():
    id = request.json["id"]

    auth = session.query(User).filter(User.name == id)

    if auth.scalar():
        return {
                   "message": "overlap"
               }, 400
    else:
        return {"message": "usable"}, 200


@app.route('/login', methods=['POST'])
def login():
    id = request.json['id']
    password = request.json['password']

    user = session.query(User).filter(User.id == id)

    if not user.scalar():
        abort(409, 'user id code does not match')

    user = user.first()
    check_user_pw = check_password_hash(user.password, password)

    if not check_user_pw:
        abort(409, 'user password code does not match')

    access_expires_delta = timedelta(minutes=60)
    refresh_expires_delta = timedelta(weeks=1)

    access_token = create_access_token(expires_delta=access_expires_delta,
                                       identity=id
                                       )
    refresh_token = create_refresh_token(expires_delta=refresh_expires_delta,
                                         identity=id
                                         )
    return {
               'access_token': access_token,
               'refresh_token': refresh_token
           }, 201


@app.route('/post', methods=['POST'])
@jwt_required()
def post():
    title = request.json['title']
    content = request.json['content']

    new_post = Post(
        title=title,
        content=content,
        created_at=datetime.datetime.now()
    )

    session.add(new_post)
    session.commit()

    return {
               "message": "success"
           }, 201


@app.route('/post', methods=['GET'])
@jwt_required()
def post_get():
    posts = session.query(Post).all()

    if posts:
        return {
                   "posts": [{
                       "title": post.title,
                       "content": post.content,
                       "created_at": str(post.created_at)
                   } for post in posts]
               }, 200

    else:
        return abort(404, 'There is not any post')


@app.route('/post/<int:id>', methods=['DELETE'])
@jwt_required()
def post_delete(id):
    post_del = session.query(Post).firter(Post.id_pk == id)

    if not post_del.scalar():
        raise NotFound('Not Find')

    post_del.delete()
    session.commit()

    return {
               'message': 'success'
           }, 200


@app.route('/comment', methods=['POST'])  # comment?post_id=1
@jwt_required()
def comment_post():
    post_id = request.args.get('post_id')
    content = request.json["content"]
    user_id = get_jwt_identity()

    new_comment = Comment(
        post_id=post_id,
        content=content,
        user_id=user_id,
        created_at=datetime.datetime.now()
    )

    session.add(new_comment)
    session.commit()

    return {
               'message': 'success'
           }, 200


@app.route('/comment', methods=['GET'])
@jwt_required()
def comment_get():
    post_id = request.args.get('post_id')

    comment_join = session.query(
        Comment.content,
        User.name
    ).join(User, User.id == Comment.user_id) \
        .filter(Comment.post_id == post_id)

    return {
               "comment_join": [{
                   "name": name,
                   "content": content
               } for name, content in comment_join]
           }, 201


if __name__ == '__main__':
    app.config['SECRET_KEY'] = 'super-secret'
    app.run(debug=True)
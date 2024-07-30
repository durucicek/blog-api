from flask import (
    Blueprint, jsonify, request, 
)
from flaskr.models import User, Post, LikedPosts, Tags
from flaskr.database import db
from flask_jwt_extended import current_user, jwt_required

bp = Blueprint('blog', __name__)

@bp.route('/create', methods=['POST'])
@jwt_required()
def create():
    data = request.get_json()
    title = data.get('title')
    body = data.get('body')
    selected_tags = data.get('tags')
    if not title:
        return jsonify({'error': 'Title is required'}), 400
    else:
        post = Post(title=title, body=body, author_id=current_user.id)
        for tag_id in selected_tags:
            tag = Tags.query.get(tag_id)
            if tag:
                post.tags.append(tag)
        db.session.add(post)
        db.session.commit()
        return jsonify({'success': True, 
                        'postId': post.id,
                        'title': post.title,
                        'body': post.body,
                        'author': post.author.username,
                        'tags': [tag.name for tag in post.tags]
                        }), 201

def get_post(id, check_author=True):
    stmt = db.select(Post).join(User, Post.author_id == User.id).where(Post.id == id)
    post = db.session.execute(stmt).scalar()
    if post is None:
        return jsonify({"message": f"Post id {id} doesn't exist."}),404
    if check_author and post.author_id != current_user.id:
        return jsonify({"message": "Don't have permission to update"}),404
    return post

@bp.route('/update/<int:post_id>', methods=('GET', 'POST'))
#@login_required
@jwt_required()
def update(post_id):
    post = get_post(post_id)
    if request.method == 'GET':
        selected_tags = [tag.id for tag in post.tags]

    if request.method == 'POST':
        data = request.get_json()
        title = data.get('title')
        body = data.get('body')
        selected_tags = data.get('tags')
        if not title:
            return jsonify({'error': 'Title is required'}), 400
        else:
            post.title = title
            post.body = body
            stmt = db.select(Tags).where(Tags.id.in_(selected_tags))
            post.tags = db.session.execute(stmt).scalars().all()
            db.session.commit()
            return jsonify({'success': True, 
                            'postId': post.id,
                            'title': post.title,
                            'body': post.body,
                            'author': post.author.username,
                            'tags': [tag.name for tag in post.tags]
                            }), 200

@bp.route('/delete/<int:id>', methods=('POST',))
#@login_required
@jwt_required()
def delete(id):
    post = get_post(id)
    db.session.delete(post)
    db.session.commit()
    return jsonify({'success': True, 'message': f"Post id {id} deleted"}), 200

@bp.route('/like/<postid>', methods=['POST'])
#@login_required
@jwt_required()
def like(postid):
    try:
        postid = int(postid)
    except ValueError:
        return jsonify({'error': 'Post ID must be integers'}), 400
    user = current_user
    post = Post.query.get(postid)
    if user is None:
        return jsonify({'error': "User doesn't exist"}), 404
    if post is None:
        return jsonify({'error': "Post doesn't exist"}), 404
    
    userid = user.id
    stmt = db.select(LikedPosts).where(LikedPosts.user_id == userid, LikedPosts.post_id == postid)
    liked_post = db.session.execute(stmt).scalar()
    if liked_post is None:
        post.likes += 1
        new_like = LikedPosts(user_id=userid, post_id=postid)
        db.session.add(new_like)
    else:
        post.likes -= 1
        db.session.delete(liked_post)

    db.session.commit()
    return jsonify({'success': True, 'likes': post.likes}), 200

@bp.route('/add-tag', methods=['POST'])
#@login_required
@jwt_required()
def add_tag():
    tag_name = request.json.get('tag_name')
    if not tag_name:
        return jsonify({'success': False, 'error': 'Tag name is required'}), 400

    stmt = db.select(Tags).where(Tags.name == tag_name)
    existing_tag = db.session.execute(stmt).scalar()

    if existing_tag:
        return jsonify({'success': False, 'error': 'Tag already exists'}), 409

    new_tag = Tags(name=tag_name)
    db.session.add(new_tag)
    db.session.commit()

    return jsonify({'success': True, 'tagId': new_tag.id, 'tagName': new_tag.name}), 201

@bp.route('/tags', methods=['GET'])
def get_tags():
    tags = db.session.execute(db.select(Tags)).scalars().all()
    return jsonify({'tags': [tag.name for tag in tags]}), 200

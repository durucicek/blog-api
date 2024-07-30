from sqlalchemy import ForeignKey, String, DateTime, Integer, Table, Column, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from flaskr.database import db
from typing import List
from flaskr.database import Base


class User(db.Model):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(128), nullable=False)

    posts: Mapped[List["Post"]] = relationship(back_populates="author")
    liked_posts: Mapped[List["LikedPosts"]] = relationship(back_populates="user")

    def __repr__(self) -> str:
        return f"User(id={self.id!r}, username={self.username!r}, password={self.password!r})"

class Post(db.Model):
    __tablename__ = "post"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created: Mapped[DateTime] = mapped_column(DateTime, nullable=False, default=func.now())
    title: Mapped[str] = mapped_column(String(100), nullable=False)
    body: Mapped[str] = mapped_column(String(300), nullable=False)
    likes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    author_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    author: Mapped["User"] = relationship(back_populates="posts")

    liked_posts: Mapped[List["LikedPosts"]] = relationship(back_populates="post",cascade="all, delete-orphan")

    tags: Mapped[List["Tags"]] = relationship(secondary= "tags_post", back_populates="post")

    def __repr__(self) -> str:
        return f"<Post(id={self.id!r}, author_id={self.author_id!r}, title={self.title!r}, body={self.body[:50]}...)>"


class LikedPosts(db.Model):
    __tablename__ = "liked_posts"
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'), primary_key=True, nullable=False)
    post_id: Mapped[int] = mapped_column(ForeignKey('post.id'), primary_key=True, nullable=False)

    user : Mapped["User"] = relationship(back_populates="liked_posts")
    post : Mapped["Post"] = relationship(back_populates="liked_posts")

    def __repr__(self) -> str:
        return f"<LikedPosts(user_id={self.user_id!r}, post_id={self.post_id!r})>"

class Tags(db.Model):
    __tablename__ = "tags"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)

    post: Mapped[List["Post"]] = relationship(secondary= "tags_post", back_populates="tags")

    def __repr__(self) -> str:
        return f"<Tags(id={self.id!r}, name={self.name!r})>"
    
tags_post = Table(
    "tags_post",
    Base.metadata,
    Column("post_id", ForeignKey("post.id")),
    Column("tag_id", ForeignKey("tags.id")),
)
 
from datetime import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
  __tablename__ = 'user'
  email = Column(String(250),primary_key = True)
  id = Column(Integer, autoincrement=True)
  name =Column(String(80), nullable = False)
  picture = Column(String(250))
  created_date = Column(DateTime, default=datetime.utcnow)
  @property
  def serialize(self):
     """Return object data in easily serializeable format"""
     return {
         'name'         : self.name,
         'id'           : self.id,
         'picture_path' : self.picture,
         'created_date' : self.created_date,
         'email'        : self.email
     }

class Category(Base):
  __tablename__ = 'category'
  id = Column(Integer, autoincrement=True,primary_key = True)
  name = Column(String(80), nullable = False)
  desc = Column(String(250))
  user_id = Column(String(250),ForeignKey('user.email'))
  user = relationship(User)
  created_date = Column(DateTime, default=datetime.utcnow)
  @property
  def serialize(self):
     """Return object data in easily serializeable format"""
     return {
         'name'         : self.name,
         'id'           : self.id,
         'desc'         : self.desc,
         'creator'      : self.user_id,
         'created_date' : self.created_date
     }

class Item(Base):
  __tablename__ = 'items'

  id = Column(Integer, primary_key=True)
  name = Column(String(250), nullable=False)
  desc = Column(String(250))
  category_id = Column(Integer,ForeignKey('category.id'))
  category = relationship(Category)
  user_id = Column(String(250),ForeignKey('user.email'))
  user = relationship(User)
  created_date = Column(DateTime, default=datetime.utcnow)
  @property
  def serialize(self):
     """Return object data in easily serializeable format"""
     return {
         'id'           : self.id,
         'name'         : self.name,
         'desc'         : self.desc,
         'category'     : self.category_id,
         'user'         : self.user_id,
         'created_date' : self.created_date

     }

engine = create_engine('sqlite:///items.db')

Base.metadata.create_all(engine)

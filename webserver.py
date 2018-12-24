from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import Base, Item, Category, User

app = Flask(__name__)

# binds the app to the db and creates a db session
engine = create_engine('sqlite:///items.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

if __name__ == '__main__':
	app.secret_key = 'secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)
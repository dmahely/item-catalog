from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import Base, Category, User, Item
import datetime

engine = create_engine('sqlite:///items.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# delete existing data
session.query(Item).delete()
session.query(Category).delete()
session.query(User).delete()

# Some users
user1 = User(name="Doaa",
             email="dom.9k@icloud.com",
             picture="https://avatars0.githubusercontent.com/u/21047475?s=400&u=c9569dfe73b594676d80aa2f991797d71ed6bace&v=4")
session.add(user1)
session.commit()

print("Users added")

# Some categories
category1 = Category(name="Soccer",
                     user_id=1)
session.add(category1)
session.commit()

category2 = Category(name="Rugby",
                     user_id=1)
session.add(category2)
session.commit()

print("Categories added")

# Some items
item1 = Item(name="Coffee Mug",
	description="A soccer-themed coffee mug for the ultimate fan",
	price="$8",
	date_added=datetime.datetime.now(),
	category_id=1,
	user_id=1)
session.add(item1)
session.commit()

print("Items added")

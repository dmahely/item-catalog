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

# Some categories
category1 = Category(name="Soccer")
session.add(category1)
session.commit()

category2 = Category(name="Rugby")
session.add(category2)
session.commit()

print("Categories added")

# Some items
item1 = Item(name="Coffee Mug",
	description="A soccer-themed coffee mug for the ultimate fan",
	price="$8",
	date_added=datetime.datetime.now(),
	category_id=1,
	user_id=None)
session.add(item1)
session.commit()

print("Items added")
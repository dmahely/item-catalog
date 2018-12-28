# Item Catalog

_This project is the fourth project in the curriculum of Udacity’s Full Stack Web Developer Nanodegree._ This project uses Python, Flask and SQLAlchemy to create a database of categories and items and a CRUD web application. It uses Google authentication and a local permission system for user authorization. The project was styled using Bootstrap.

# Before Running the Program
You must have Python installed on your machine. Check your Python version by running `python -V`.

# Running the Program
1. Install [VirtualBox](https://www.virtualbox.org/wiki/Download_Old_Builds_5_1)
2. Install [Vagrant](https://www.vagrantup.com)
3. Install [Git](https://git-scm.com/downloads)
4. Download [this repository](https://github.com/udacity/fullstack-nanodegree-vm). Click on the green `Clone or download` button, then click on `Download ZIP`. There's no need to log in or make a GitHub account. This will give you a directory named `fullstack-nanodegree-vm-master`. You will most likely find it in your `Downloads` folder.
5. Navigate to the `vagrant` directory inside of `fullstack-nanodegree-vm-master`.
6. Open the terminal app on your Mac or the command prompt on your Windows machine and run `vagrant up`. This may take some time as it will install an OS on your machine. Don't be alarmed by the green and red lines showing on your screen.
7. Run `vagrant ssh`.
8. Run `cd /vagrant`. This will take you to the shared folder between your VM and host machine.
9. Download this repository (dmahely/item-catalog) and place its contents in `fullstack-nanodegree-vm-master/vagrant/`.
10. Run `python db_setup`. This command will create a file named `items.db` in the same directory.
11. Run `python db_population.py`. This command will populate the database with some items and categories.
12. Run `python webserver.py`. This command will get the server up and running.
13. Go to [http://localhost:5000/](http://localhost:5000/) in your browser.

# After Running the Program
You should see a webpage that has some categories and some items.

# Acknowledgements
I wrote all of the code except for the gconnect and gdisconnect methods, which were provided to me in a course by Udacity. I was inspired by how Dustin D'Avignon styled [his own web app](https://github.com/ddavignon/item-catalog) and decided to use Bootstrap to style mine as well.

Welcome to CATALOG APP Installation Guide:

In order ot install the app, follow the following steps:

THIS CODE HAS BEEN DEVELOPED BASED ON THE TEMPLATE PROVIDED BY UDACITY

RUNNING THE APPLICATION

1. Pull repository into the local machine inside the catalog folder in the
   vagrant working folder
2. Start the virtual machine by performing 'vagrant up' command in the terminal
   and 'vagrant ssh'
3. When in the VM type 'cd vagrant' to navigate to the host computer's vagrant
   folder shared with the VM
4. Run 'python projectItemLists.py' in order to run the application. This will
   create the items.db database and start the web app in http://localhost:5000

Examples for accessing the web services:

1. http://localhost:5000/category/2/item/JSON
2. http://localhost:5000/category/JSON
3. http://localhost:5000/item/1/JSON
4. http://localhost:5000/allitems/JSON
5. http://localhost:5000/user/JSON
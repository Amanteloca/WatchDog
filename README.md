Flask User Authentication ProjectThis is a simple Flask web application that provides user authentication features including 

* user registration 
* login 
* logout 
* protected home page.

Features
User Registration: Allow users to create accounts with a unique username, password, and email address.

User Login: Authenticate users based on their credentials.

Session Management: Use Flask session to keep track of logged-in users.

Home Page: Display a home page accessible only to logged-in users.

Logging: Implement logging to capture important events and errors.

Prerequisites

Before you begin, ensure you have the following installed:Python (3.6 or higher)Flask (pip install Flask)Flask-MySQLdb (pip install Flask-MySQLdb) or another MySQL driver of your choiceMySQL serverSetupClone the Repository:git clone https://github.com/yourusername/your-repo.

gitInstall Dependencies:pip install -r requirements.txtDatabase Setup:Create a MySQL database and update the configuration in app.py with your database details.

Logging Setup:Configure the logging settings in app.py based on your preferences.

Run the Application:python app.pyThe application will be accessible at http://localhost:5000.Project 
Structure/your-repo
│   app.py
│   requirements.txt
│   README.md
│
└───templates
│       error.html
│       home.html
│       index.html
│       register.html
│
└───static
        /css
            style.cssUsageUser Registration:Visit http://localhost:5000/pythonlogin/register to register a new account.
            
            User Login:Go to http://localhost:5000/pythonlogin/ to log in using your registered credentials.
            
            Home Page:After logging in, visit http://localhost:5000/pythonlogin/home to access the home page.
            
            Logging:Check the logs in the app.log file for important events and errors.
            
            Team Members
            Kennedy kpor
            Beatrice Addison Winful
            Anthony Yeboah

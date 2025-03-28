```python
#!/usr/bin/python3

from flask import Flask, request, render_template, render_template_string, make_response, redirect, url_for

import socket

  

app = Flask(__name__)

  

try:

    FLAG = open('./flag.txt', 'r').read()

except:

    FLAG = '[**FLAG**]'

  

app.secret_key = FLAG

  
  

@app.route('/')

def index():

    return render_template('index.html')

  

@app.errorhandler(404)

def Error404(e):

    template = '''

    <div class="center">

        <h1>Page Not Found.</h1>

        <h3>%s</h3>

    </div>

''' % (request.path)

    return render_template_string(template), 404

  

app.run(host='0.0.0.0', port=8000)
```

We can see that the @app.errorhandler will try to render "Page Not Found" and whatever the request.path is
![[Pasted image 20250302142638.png]]

If I try a `{{}}` payload, it returns internal error
![[Pasted image 20250302142716.png]]

But since I see that the flag is in the secret_key, Claude told me that the secret_key is a part of the config in python


![[Pasted image 20250302142758.png]]

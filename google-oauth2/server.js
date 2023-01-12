const dotenv = require("dotenv");
dotenv.config();
const express = require("express");
const url = require("url");

const {
  request_get_auth_code_url,
  getAccessToken,
  getProfileData,
} = require("./utils");

const app = express();

const port = 4000;

app.get("/auth", async (req, res) => {
  try {
    res.redirect(request_get_auth_code_url);
  } catch (ex) {
    res.sendStatus(500);
    console.error(ex);
  }
});

app.get(process.env.REDIRECT_URI, async (req, res) => {
  try {
    const authCode = req.query.code;
    const response = await getAccessToken(authCode);
    const { access_token, id_token } = response.data;
    res.redirect(
      url.format({
        pathname: "/dashboard",
        query: {
          access_token: access_token,
        },
      })
    );
  } catch (ex) {
    res.sendStatus(500);
    console.error(ex);
  }
});

app.get("/dashboard", async (req, res) => {
  const response = await getProfileData(req.query.access_token);
  const { name, picture, email } = response.data;
  res.send(`
      <img src="${picture}" alt="user_image" />
      <h1>Welcome ${name}</h1>
      <h2> Email: ${email}</h2>
  `);
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

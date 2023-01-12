// ./src/index.js

//importing the dependencies
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

// in-memory "database"
let toDos = [
  { id: 1, title: 'Buy Pizza', description: 'Ask for double pepperoni.' },
  { id: 2, title: 'Pay Bills', description: 'They never stop coming.' },
  {
    id: 3,
    title: 'Submit Expenses',
    description: 'I still have to submit the expenses for that business trip.'
  }
];

// defining the Express app
const app = express();

// adding Helmet to enhance your API's security
app.use(helmet());

// using bodyParser to parse JSON bodies into JS objects
app.use(bodyParser.json());

// enabling CORS for all requests (not very secure)
app.use(cors());

// adding morgan to log HTTP requests
app.use(morgan('combined'));

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.OIDC_PROVIDER}/.well-known/jwks.json`
  }),

  // Validate the audience and the issuer.
  audience: process.env.API_IDENTIFIER,
  issuer: `https://${process.env.OIDC_PROVIDER}/`,
  algorithms: ['RS256']
});

app.use(checkJwt);

function hasScope(requiredScope) {
  return function(req, res, next) {
    const { scope } = req.user;
    const scopeArray = scope.split(' ');
    if (!scopeArray.includes(requiredScope)) {
      return res.status(403).send({ message: 'Insufficient authorization.' });
    }
    next();
  };
}

// endpoint to return all to dos
app.get('/', hasScope('read:to-dos'), (req, res) => {
  res.send(toDos);
});

app.post('/', hasScope('create:to-dos'), (req, res) => {
  toDos.push(req.body);
  res.send({ message: 'New to-do item inserted.' });
});

// endpoint to delete a to-do
app.delete('/:id', hasScope('delete:to-dos'), async (req, res) => {
  toDos = toDos.filter(element => element.id !== parseInt(req.params.id));
  res.send({ message: 'To-do item removed.' });
});

// endpoint to update a to-do item
app.put('/:id', hasScope('update:to-dos'), async (req, res) => {
  const updatedToDo = toDos.find(
    element => element.id === parseInt(req.params.id)
  );
  if (!updatedToDo) return res.status(404).send();
  updatedToDo.title = req.body.title;
  updatedToDo.description = req.body.description;
  res.send({ message: 'To-do item updated.' });
});

// start the server
app.listen(process.env.PORT || 3001, async () => {
  console.log(`listening on port ${process.env.PORT || '3001'}`);
});

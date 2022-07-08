'use strict';

const fetch = require('node-fetch');
const { Octokit } = require("@octokit/core");
const AWS = require('aws-sdk');
const jsonwebtoken = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const utf8 = require('utf8');
const base64 = require('base-64');

const dynamo = new AWS.DynamoDB.DocumentClient();

// Constant variable declarations
const cognitoKeysURL = "REDACTED";
const reCaptchaURL = "https://recaptcha.google.com/recaptcha/api/siteverify";
const reCaptchaSecret = "REDACTED";
const githubToken = "REDACTED";

/**
 * The cEDH Decklist Database API, meant for handling submissions and edits
 */
exports.handler = async (event, context, callback) => {
  try {
    if (!event.body || !JSON.parse(event.body).method) {
      return complete(400, "Missing request parameters.");
    }
    const body = JSON.parse(event.body);
    
    if (body.rc) {
      return await handleSubmission(body);
    } else if (body.jwt) {
      return await handleConsole(body);
    } else {
      return complete(400, "Missing request parameters.");
    }
    
  } catch (error) {
    //return complete(400, "An error occurred.", error.message);
    let response = {};
    response.statusCode = 400;
    response.headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    };
    let body = { "message": error.message };
    response.body = JSON.stringify(body);
    return response;
  }
};

// Handles methods which are user-submitted
async function handleSubmission(body) {
  const reCaptcha = await checkReCaptcha(body.rc);
  if (!reCaptcha.success) {
    return complete(401, "Invalid ReCaptcha");
  }
  
  const update = await checkUpdate("database");
  if (update.active) {
    return complete(409, "There is currently an update processing. Please resubmit in a few minutes.");
  }
  let fields;
  
  switch (body.method) {
    case "SUBMIT_DECK":
        fields = hasFields(body, ["data"]);
        if (!fields.success) { return fields.complete }
        return await submit.deck(body.data);
        break;
    case "SUBMIT_REQUEST":
        fields = hasFields(body, ["data"]);
        if (!fields.success) { return fields.complete }
        return await submit.request(body.data);
        break;
    default:
        return complete(400, "Invalid method name.");
  }
}

// Handles methods that Curators use to edit the database
async function handleConsole(body) {
  let user = await authenticateCurator(body.jwt);
  if (!user.authorized) {
    return complete(401, "Unauthorized user", user.error);
  } else if (user.expired) {
    return complete(401, "Login expired, please log in again.");
  }
  
  const update = await checkUpdate("database");
  if (update.active) {
    return complete(409, update.user + " has initiated a database update. Please wait a few minutes for the update to publish, then try again");
  }
  let fields;
  
  switch (body.method) {
    case "LOGIN":
      return complete(200, "Successfully logged in " + user.username, user);
      break;
    case "READ_REQUESTS":
      return await console.readRequests();
      break;
    case "DELETE_REQUEST":
      // Required Fields: jwt, id
      fields = hasFields(body, ["id"]);
      if (!fields.success) { return fields.complete }
      return await console.deleteRequest(body.id);
      break;
    case "READ_DECKS":
      return await console.readDecks();
      break;
    case "GET_DECK":
      fields = hasFields(body, ["id"]);
      if (!fields.success) { return fields.complete }
      return await console.getDeck(body.id);
      break;
    case "UPDATE_DECK":
      fields = hasFields(body, ["data", "timestamp"]);
      if (!fields.success) { return fields.complete }
      return await console.updateDeck(body.data, body.timestamp, user);
      break;
    case "PUBLISH_CHANGES":
      fields = hasFields(body, ["changes"]);
      if (!fields.success) { return fields.complete }
      return await console.publishChanges(user, body.changes);
      break;
    case "MODIFY_SITE":
      fields = hasFields(body, ["file", "content"]);
      if (!fields.success) { return fields.complete }
      return await console.modifySite(body.file, body.content, user);
      break;
    case "UPDATE_CHANGELOG":
      fields = hasFields(body, ["file", "date", "title", "content"]);
      if (!fields.success) { return fields.complete }
      return await console.updateChangelog(body.file, body.date, body.title, body.content, user);
      break;
    default:
        return complete(400, "Invalid method name.");
  }
}

/** Helper Functions and Objects **/
// Object which holds all user Submit methods
const submit = {
  request: async function(data) {
    try {
      const request = generateRequest(data);
      const result = await dynamo.put({ TableName: "Requests", Item: request }).promise();
      return complete(201, "Successfully submitted the request!");
    } catch (error) {
      return complete(500, error.message);
    }
  },
  
  deck: async function(data) {
    try {
      const request = generateDeck(data);
      const result = await dynamo.put({ TableName: "Decks", Item: request }).promise();
      return complete(201, "Successfully submitted the deck!");
    } catch (error) {
      return complete(500, error.message);
    }
  }
}

const console = {
  readRequests: async function() {
    try {
      const result = await dynamo.scan({ TableName: "Requests" }).promise();
      return complete(200, "Successfully read requests.", result.Items);
    } catch (error) {
      return complete(500, error.message);
    }
  },
  
  deleteRequest: async function(id) {
    try {
      const result = await dynamo.update({ 
        TableName: "Requests", 
        Key: { id: id },
        AttributeUpdates: {
          "deleted": {
            Action: "PUT",
            Value: true
          },
          "ttl": {
            Action: "PUT",
            Value: Math.floor(Date.now()/1000) + 604800
          }
        }
      }).promise();
      return complete(200, "Successfully deleted " + id, result);
    } catch (error) {
      return complete(500, error.message);
    }
  },
  
  readDecks: async function() {
    try {
      const params = {
        TableName: "Decks"
      };
      var safety = 0;
      const scanResults = [];
      let items;
      do {
        safety = safety + 1;
        if (safety > 50) {
          return complete(500, "Too many scan iterations - please don't bankrupt me.");
        }
        items =  await dynamo.scan(params).promise();
        items.Items.forEach((item) => scanResults.push(item));
        params.ExclusiveStartKey = items.LastEvaluatedKey;
      } while (typeof items.LastEvaluatedKey !== "undefined");
      
      return complete(200, "Successfully read decks.", JSON.stringify(scanResults));
    } catch (error) {
      return complete(500, error.message);
    }
  },
  
  getDeck: async function(id) {
    try {
      const result = await dynamo.get({ 
        TableName: "Decks", 
        Key: {
          id: id
        } 
      }).promise();
      return complete(200, "Successfully retrieved the deck", result.Item);
    } catch (error) {
      return complete(500, error.message);
    }
  },
  
  updateDeck: async function(data, timestamp, curator) {
    try {
      const getResult = await dynamo.get({ 
        TableName: "Decks", 
        Key: {
          id: data.id
        } 
      }).promise();
      
      const item = getResult.Item;
      
      if (item.updated > timestamp) {
        return complete(409, item.editor + " made changes to this deck since you've began. Please review their version of the listing before resubmitting.", item);
      }
      
      if (item.status !== "PUBLISHED" && data.status === data.destination) {
        data.destination = null;
      } else if (data.status === "DELETED" && data.destination === "SUBMITTED") {
        data.status = "SUBMITTED";
        data.destination = null;
      } else if (data.status === "DELETED" && data.destination === "PUBLISHED") {
        data.status = "SUBMITTED";
        data.destination = "PUBLISHED";
      }
      
      const deck = generateDeck(data, curator);
      const putResult = await dynamo.put({ TableName: "Decks", Item: deck }).promise();
      
      return complete(200, "Successfully updated the deck", putResult.Item);
    } catch (error) {
      return complete(500, error.message);
    }
  },
  
  publishChanges: async function(curator, changes) {
    try {
      const update = await checkUpdate("database");
      const cooldown = (Date.now() - update.timestamp);
      if (cooldown < 30000) {
        const minutes = Math.floor(((30000 - cooldown) / 6000)) / 10;
        return complete(403, "There has already been an update recently, which was initiated by " + update.user + ". Publishing will be available in " + minutes + " minutes");
      }
      
      await setUpdate(true, "database", curator);
      
      const file = "https://raw.githubusercontent.com/AverageDragon/cEDH-Decklist-Database/master/_data/database.json";
      const data = await fetch(file).then(v => { return v.json() });
      
      var batchKeys = [];
      JSON.parse(changes).forEach(deckId => batchKeys.push({ "id": deckId }));
      
      
      
      var safety = 0;
      let batches = [];
      
      do {
        safety = safety + 1;
        if (safety > 50) {
          return complete(500, "Too many batchGetItems iterations - please don't bankrupt me.");
        }
        
        let sliceBatchKeys = batchKeys.slice(0, 20);
        batchKeys.splice(0, 20);
        let batchParams = {
          "RequestItems": {
            "Decks": {
              Keys: sliceBatchKeys
            }
          }
        }
        
        let batch = await dynamo.batchGet(batchParams).promise();
        batches.push(batch);
        
      } while (batchKeys.length > 0);
      
      const deckSet = {};
      data.forEach(deck => { deckSet[deck.id] = deck; });
      
      const promises = [];
      for (let i = 0; i < batches.length; i++) {
        let thisBatch = batches[i];
        if (typeof thisBatch["Responses"] == "undefined") {
          break;
        }
        thisBatch["Responses"]["Decks"].forEach(item => {
          const value = item.destination ? item.destination : item.status;
          let attributeValues = { ":null": null, ":value": value };
          let updateExpression = "SET #dstatus = :value, #ddest = :null";
          
          if (value === "DELETED") {
            updateExpression = updateExpression + ", #dttl = :ttl";
            attributeValues[":ttl"] = Math.floor(Date.now()/1000) + 604800;
            delete deckSet[item.id];
          } else {
            updateExpression = updateExpression + ", #dttl = :null";
          }
          const updateParams = {
            TableName: "Decks",
            Key: { id: item.id },
            ExpressionAttributeValues: attributeValues,
            ExpressionAttributeNames: { "#dstatus": "status", "#ddest": "destination", "#dttl": "ttl" },
            UpdateExpression: updateExpression
          }
          promises.push(dynamo.update(updateParams).promise());
          if (item.destination === "PUBLISHED" || (item.status === "PUBLISHED" && !item.destination)) {
            delete item.comments;
            delete item.editor;
            delete item.status;
            delete item.destination;
            delete item.ttl;
            deckSet[item.id] = item;
          }
        });
      }
      
      
      await Promise.all(promises);
      await alterGithub(true, "_data/database.json", curator.username + " published database changes", utf8.encode(JSON.stringify(Object.values(deckSet))));
      
      await setUpdate(false, "database", curator);
      return complete(200, "Successfully updated the database.");
    } catch (error) {
      await setUpdate(false, "database", curator);
      return complete(500, error.message);
    }
  },
  
  modifySite: async function(file, content, curator) {
    const files = {
      "MOTD": "motd.md",
      "ABOUT": "about.md",
      "TEMPLATE": "template.md",
      "SUBMIT": "submit.md",
      "REQUEST": "request.md",
      "COMPETITIVE": "tables/competitive.md",
      "BREW": "tables/brew.md",
      "DEPRECATED": "tables/deprecated.md",
      "MEME": "tables/meme.md"
    };
    if (!Object.keys(files).includes(file)) {
      return complete(404, "Invalid file name.");
    }
    try {
      const update = await checkUpdate(file);
      const cooldown = (Date.now() - update.timestamp);
      if (cooldown < 1800000) {
        const minutes = Math.floor(((1800000 - cooldown) / 6000)) / 10;
        return complete(403, "This file has been updated recently by " + update.user + ". This file can be edited again in " + minutes + " minutes");
      }
      
      await setUpdate(true, file, curator);
      
      const decoded = base64.decode(content);
      if (decoded.length > 100000) {
        throw new Error("That file is too long. Please be careful about breaking the site.");
      }
      const message = curator.username + " updated " + files[file];
      await alterGithub(true, "_includes/markdown/" + files[file], message, decoded);
      
      await setUpdate(false, file, curator);
      return complete(200, "Successfully updated the " + file + " file!");
    } catch (error) {
      await setUpdate(false, file, curator);
      return complete(500, error.message);
    }
  },
  
  updateChangelog: async function(file, date, title, content, curator) {
    try {
      const update = await checkUpdate("changelog");
      const cooldown = (Date.now() - update.timestamp);
      if (cooldown < 1800000) {
        const minutes = Math.floor(((1800000 - cooldown) / 6000)) / 10;
        return complete(403, "The changelog has been edited recently by " + update.curator + ". It can be edited again in " + minutes + " minutes");
      }
      
      await setUpdate(true, "changelog", curator);
      
      const markdown = base64.decode(content);
      const updateTitle = base64.decode(title);
      const filename = file === "new" ? "u" + new Date().getTime() : file;
      const filedate = file === "new" ? new Date().toISOString() : date;
      const oldFile = file !== "new";
      
      
      if (markdown.length > 100000 || updateTitle.length > 100) {
        throw new Error("Your input is too long. Please be careful about breaking the site.");
      }
      
      const fullChangelog = "---\ntitle: " 
                            + updateTitle + "\nfilename: " 
                            + filename + "\ndate: "
                            + filedate + "\n---\n" + markdown;
      const message = curator.username + " updated changelog " + updateTitle;
      await alterGithub(oldFile, "_includes/markdown/_updates/" + filename + ".md", message, fullChangelog);
      
      await setUpdate(false, "changelog", curator);
      return complete(200, "Successfully updated the changelog entry for " + updateTitle + "!");
    } catch (error) {
      await setUpdate(false, "changelog", curator);
      return complete(500, error.message);
    }
  }
}

// Generates the fields needed for a return statement.
function complete(code, message, data = null) {
  let response = {};
  response.statusCode = code;
  response.headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  };
  let body = { "message": message };
  if (data) {
    body.data = data;
  }
  response.body = JSON.stringify(body);
  return response;
}

async function checkUpdate(key) {
  // id: "update"
  // timestamp: Date.now()
  // active: boolean
  // user: string
  
  // Date.now() - timestamp > 86400000
  const update = await dynamo.get({ 
    TableName: "Update", 
    Key: { id: key } 
  }).promise();
  
  return update.Item;
}

async function setUpdate(active, key, user) {
  const update = {
    id: key,
    active: active,
    timestamp: Date.now(),
    user: user.username
  };
  
  await dynamo.put({ TableName: "Update", Item: update }).promise();
}

/*
 * update: Boolean indicating if this is a new file or updating a file
 * path: Path to the file which is being altered
 * message: The commit message which will appear on Github
 * content: The acutal file contents which will be put on github, as a string
 */
async function alterGithub(update, path, message, content) {
  const octokit = new Octokit({ auth: githubToken });
  
  const parameters = {
    owner: "AverageDragon",
    repo: "cEDH-Decklist-Database",
    path: path
  }
  
  if (update) {
    parameters.sha = await octokit.request("GET /repos/{owner}/{repo}/contents/{path}", parameters)
      .then(v => v.data.sha);
  }
  
  parameters.message = message;
  parameters.content = Buffer.from(content, 'binary').toString('base64');
  
  const result = await octokit.request("PUT /repos/{owner}/{repo}/contents/{path}", parameters);
}

// Checks that the object has the required fields
function hasFields(body, args) {
  let fields = { success: true, missing: [] };
  for (let i = 0; i < args.length; i++) {
    if (!(args[i] in body)) {
      fields.success = false;
      fields.missing.push(args[i]);
    }
  }
  fields.complete = complete(400, "Missing fields: " + fields.missing.toString());
  return fields;
}

// Authenticates a curator in order to grant them permissions
// If not authenticated or authentication is invalid, returns false.
// Otherwise, returns the jwt, username, and login expiration time
async function authenticateCurator(jwt) {
  try {
    const store = await fetch(cognitoKeysURL, {
      method: "GET",
      headers: {
        "Content-Type": "application/json"
      }
    }).then(resp => resp.json());
    
    const decoded = jsonwebtoken.decode(jwt, {complete: true}).header;
    let pem;
    for (let i = 0; i < store.keys.length; i++) {
      let key = store.keys[i];
      if (key.kid === decoded.kid) {
        pem = jwkToPem(key);
        break;
      }
    }
    
    let result = jsonwebtoken.verify(jwt, pem, { algorithms: ['RS256'] });
    return {
      authorized: true,
      expired: false,
      jwt: jwt,
      username: result["cognito:username"],
      exp: result["exp"]
    };
  } catch (error) {
    if (error.message === "jwt expired") {
      return { authorized: true, expired: true }; 
    } else {
      return { authorized: false, error: error.message };
    }
  }
}

// Verifies that a submitted ReCaptcha is valid
async function checkReCaptcha(rc) {
  try {
    const completeURL = reCaptchaURL 
    + "?secret=" + reCaptchaSecret 
    + "&response=" + rc;
    const res = await fetch(completeURL, {
      method: "POST"
    }).then(resp => resp.json());
    return { success: res.success, message: res };
  } catch (error) {
    return { success: false, message: error.message };
  }
}

/* Validation constants */
const v = {
  enum: {
    colors: ["w", "u", "b", "r", "g"],
    section: ["COMPETITIVE", "BREW", "DEPRECATED", "MEME"],
    status: ["PUBLISHED", "DELETED", "SUBMITTED"]
  },
  length: {
    short: 100,
    medium: 300,
    long: 1000
  },
  pattern: {
    discord: /(https?:\/\/)?(www\.)?(discord\.(gg|io|me|li)|(discordapp|discord)\.com\/invite)\/.+./g,
    link: /(http(s)?:\/\/.)?(www\.)?[-a-zA-Z0-9@:%._+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_+.~#?&//=]*)/g,
    discord_user: /(.+#[0-9]{4}$)/g
  }
}

/* Validation Functions */
const valid = {
  // Throw an error when an entry is invalid
  fail: function(msg) {
    throw new Error("Validation Error: " + msg);
  },
  
  // Text
  text: function(input, msg, length, pattern = null) {
    if (input === null || typeof input !== "string") {
      this.fail(msg + " - Missing text input");
    } else if (input.length > length) {
      this.fail(msg + " - Text input is longer than " + length + " characters.");
    } else if (pattern && !input.match(pattern)) {
      this.fail(msg);
    } else {
      return input;
    }
  },
  
  // Boolean
  boolean: function(input) {
    if (typeof input !== "boolean") {
      this.fail("Invalid boolean");
    } else {
      return input;
    }
  },
  
  // Section
  section: function(input) {
    if (!input || typeof input !== "string") {
      this.fail("Missing section input");
    } else if (!v.enum.section.includes(input)) {
      this.fail("Invalid section");
    } else {
      return input;
    }
  },
  
  // Status
  status: function(input) {
     if (input === null) {
      this.fail("Missing status input");
    } else if (typeof input !== "string" || !v.enum.status.includes(input)) {
      this.fail("Invalid status");
    } else {
      return input;
    }
  },
  
  // Destination
  destination: function(input) {
     if (input === null) {
      return null;
    } else if (typeof input !== "string" || !v.enum.status.includes(input)) {
      this.fail("Invalid status");
    } else {
      return input;
    }
  },
  
  // Colors
  colors: function(input) {
    if (!input || typeof input !== "object" || input.length > 5) {
      this.fail("Invalid colors");
    } else if (!input.every(val => v.enum.colors.includes(val))) {
      this.fail("Invalid colors");
    } else {
      return input;
    }
  },
  
  // Commander
  commander: function(input) {
    if (!input || typeof input !== "object" || input.length > 2 || input.length < 1) {
      this.fail("Invalid commanders");
    } else {
      const result = [];
      for (let i = 0; i < input.length; i++) {
        const commander = input[i];
        const obj = {};
        obj.name = valid.text(commander.name, "Commander Name " + i, v.length.medium);
        obj.link = valid.text(commander.link, "Commander Link " + i, v.length.medium, v.pattern.link);
      }
      return input;
    }
  },
  
  // Discord
  discord: function(input) {
    if (input === null) {
      return null;
    } else if (!input.title || !input.link) {
      this.fail("Missing Discord information");
    } else {
      let discord = {};
      discord.title = valid.text(input.title, "Discord Title", v.length.short);
      discord.link = valid.text(input.link, "Discord Link", v.length.medium, v.pattern.discord);
      return discord;
    }
  },
  
  // Decklists
  decklists: function(input) {
    if (!input || typeof input !== "object" || input.length > 30) {
      this.fail("Invalid decklists");
    } else {
      let decklists = [];
      for (let i = 0; i < input.length; i++) {
        const cur = input[i];
        let dl = {};
        dl.primer = valid.boolean(cur.primer);
        dl.link = valid.text(cur.link, "Invalid deck link for deck #" + (i + 1), v.length.medium, v.pattern.link);
        dl.title = valid.text(cur.title, "Invalid deck title for deck #" + (i + 1), v.length.short);
        decklists.push(dl);
      }
      return decklists;
    }
  }
}

// Creates an ID for use for both Submissions and Decks
function generateID() {
  return "x" + Math.random().toString(36).substr(2, 11);
}

// Takes the input info and generates a deck.
// If a curator function is being used, curator should be true
function generateDeck(info, curator = null) {
  let deck = {};
  if (curator) {
    deck.id = valid.text(info.id, "If you see this, contact AverageDragon.", v.length.medium);
    deck.comments = info.comments ? valid.text(info.comments, "Curator Comments", v.length.long) : "";
    deck.recommended = valid.boolean(info.recommended);
    deck.status = valid.status(info.status);
    deck.destination = valid.destination(info.destination);
    deck.editor = curator.username;
  } else {
    deck.id = generateID();
    deck.comments = "";
    deck.recommended = false;
    deck.status = "SUBMITTED";
    deck.destination = null;
    deck.editor = null;
  }
  if (deck.status === "DELETED" && !deck.destination) {
    deck.ttl = Math.floor(Date.now()/1000) + 604800;
  }
  deck.updated = new Date().toISOString();
  deck.colors = valid.colors(info.colors);
  deck.commander = valid.commander(info.commander);
  deck.section = valid.section(info.section);
  deck.title = valid.text(info.title, "Deck Title", v.length.short);
  deck.description = valid.text(info.description, "Deck Description", v.length.long);
  deck.decklists = valid.decklists(info.decklists);
  deck.discord = valid.discord(info.discord);
  return deck;
}

// Takes the input info and creates a new Request object
function generateRequest(info) {
  let req = {};
  req.id = generateID();
  req.category = valid.text(info.category, "Request Category", v.length.short);
  req.description = valid.text(info.description, "Request Description", v.length.long);
  if (info.username) {
    req.username = valid.text(info.username, "Discord Username", v.length.short, v.pattern.discord_user);
  } else {
    req.username = null;
  }
  req.date = new Date().toISOString();
  req.deleted = false;
  return req;
}

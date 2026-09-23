"use strict";

const WebSocket = require("ws");
const readline = require("readline");

const WS_URL = "wss://hack.chat/chat-ws";
const CHANNEL = process.argv[2] || "math";
const NICK = process.argv[3] || "hotdogs";

let socket;
let reconnectTimer;
let closing = false;

function connect() {
  console.log(`Connecting to ${WS_URL}...`);

  socket = new WebSocket(WS_URL);

  socket.on("open", () => {
    console.log(`Connected. Joining #${CHANNEL} as ${NICK}`);

    send({
      cmd: "join",
      channel: CHANNEL,
      nick: NICK
    });
  });

  socket.on("message", (raw) => {
    try {
      const data = JSON.parse(raw.toString());
      handleMessage(data);
    } catch (error) {
      console.error("Invalid server message:", raw.toString());
    }
  });

  socket.on("close", () => {
    console.log("Disconnected.");

    if (!closing) {
      reconnectTimer = setTimeout(connect, 3000);
    }
  });

  socket.on("error", (error) => {
    console.error("WebSocket error:", error.message);
  });
}

function send(message) {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    return;
  }

  socket.send(JSON.stringify(message));
}

function handleMessage(message) {
  switch (message.cmd) {
    case "chat":
      console.log(
        `[${message.nick}] ${message.text}`
      );
      break;

    case "info":
      console.log(`[INFO] ${message.text}`);
      break;

    case "onlineSet":
      console.log(
        `[USERS] ${message.nicks?.join(", ") || ""}`
      );
      break;

    case "onlineAdd":
      console.log(`[+] ${message.nick}`);
      break;

    case "onlineRemove":
      console.log(`[-] ${message.nick}`);
      break;

    case "warn":
      console.log(`[WARN] ${message.text}`);
      break;

    case "error":
      console.error(`[ERROR] ${message.text}`);
      break;

    default:
      console.log("[SERVER]", message);
  }
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> "
});

rl.prompt();

rl.on("line", (line) => {
  const text = line.trim();

  if (!text) {
    rl.prompt();
    return;
  }

  if (text === "/quit") {
    closing = true;

    if (socket) {
      socket.close();
    }

    rl.close();
    return;
  }

  if (text === "/help") {
    console.log("/quit  Disconnect");
    console.log("/help  Show commands");
    rl.prompt();
    return;
  }

  send({
    cmd: "chat",
    text
  });

  rl.prompt();
});

rl.on("close", () => {
  closing = true;

  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
  }

  process.exit(0);
});

connect();


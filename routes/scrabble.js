const express = require('express');
const router = express.Router();

// In-memory game state (for demo; use DB in production)
const games = {};
const MAX_PLAYERS = 4;
const MIN_PLAYERS = 2;
const BOARD_SIZE = 15;
const RACK_SIZE = 7;

function createEmptyBoard() {
  return Array.from({ length: BOARD_SIZE }, () => Array(BOARD_SIZE).fill(null));
}

// Create a new Scrabble room
router.post('/create', (req, res) => {
  const roomId = Math.random().toString(36).substr(2, 8);
  games[roomId] = {
    players: [],
    board: createEmptyBoard(),
    started: false,
    tileBag: [], // TODO: fill with tiles
    turn: 0,
    moves: [],
  };
  res.json({ roomId });
});

// Join a Scrabble room
router.post('/join', (req, res) => {
  const { roomId, name } = req.body;
  const game = games[roomId];
  if (!game) return res.status(404).json({ error: 'Room not found' });
  if (game.players.length >= MAX_PLAYERS) return res.status(400).json({ error: 'Room full' });
  if (game.started) return res.status(400).json({ error: 'Game already started' });
  const playerId = Math.random().toString(36).substr(2, 8);
  game.players.push({ id: playerId, name, rack: [] });
  res.json({ playerId, players: game.players });
});

// Get game state
router.get('/:roomId', (req, res) => {
  const { roomId } = req.params;
  const game = games[roomId];
  if (!game) return res.status(404).json({ error: 'Room not found' });
  res.json(game);
});

module.exports = router;
module.exports.games = games; 
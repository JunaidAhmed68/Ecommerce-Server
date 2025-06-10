import express from 'express';
import morgan from 'morgan';
import 'dotenv/config';
import mongoose from 'mongoose';
import authRoutes from './routes/auth.mjs';
import usersRoutes from './routes/users.mjs';
import cors from 'cors';

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Routes
app.use('/auth', authRoutes);
app.use('/users', usersRoutes);

app.get('/', (req, res) => {
  res.send('API is working!');
});

// Connect MongoDB (connect once when function initializes)
mongoose.connect(process.env.MONGOBD_URL)
  .then(() => console.log('MongoDB connected!'))
  .catch(err => console.error('MongoDB connection error:', err));

// ❗️Important: Do NOT call app.listen()
// ✅ Instead, export the app for Vercel
export default app;

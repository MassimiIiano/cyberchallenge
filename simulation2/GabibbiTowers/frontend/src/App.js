import './App.css';
import {
  BrowserRouter as Router,
  Routes,
  Route,
} from "react-router-dom";
import { Home } from "./pages/Home";
import { MyNavbar } from "./pages/Navbar";
import { Login } from "./pages/Login";
import { Register } from "./pages/Register";
import { PlayGame } from './pages/PlayGame';
import { CreateGame } from './pages/CreateGame';
import { Profile } from './pages/Profile';
import React, { useState } from "react";


export const UserContext = React.createContext(null);

function App() {
  const [user, setUser] = useState(null);

  return (
    <>
      <MyNavbar />
      <Router>
        <UserContext.Provider value={{ user: user, setUser: setUser }}>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/play" element={<PlayGame />} />
            <Route path="/games" element={<CreateGame />} />
            <Route path="/profile" element={<Profile />} />
          </Routes>
        </UserContext.Provider>
      </Router>
    </>
  );
}

export default App;

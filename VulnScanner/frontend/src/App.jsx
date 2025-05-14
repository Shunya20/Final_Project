// src/App.jsx
import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Navbar from './components/Navbar';
import Footer from './components/footer';
import Home from './pages/Home';
import Scan from './pages/Scan';
import About from './pages/About';
import ResultsPage from './pages/ResultsPage'; // ✅ NEW import


function App() {
  return (
    <Router>
      <Navbar />
      <div className="container mx-auto p-4">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/scan" element={<Scan />} />
          <Route path="/about" element={<About />} />
          <Route path="/results" element={<ResultsPage />} /> {/* ✅ NEW route */}
        </Routes>
      </div>
      <Footer />
    </Router>
  );
}

export default App;

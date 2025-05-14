// src/components/Navbar.jsx
import React from 'react';
import { Link } from 'react-router-dom';

const Navbar = () => {
  return (
    <nav className="bg-blue-500 p-4">
      <div className="flex justify-between items-center">
        <Link to="/" className="text-white text-2xl">VulnScanner</Link>
        <ul className="flex space-x-6 text-white">
          <li><Link to="/">Home</Link></li>
          <li><Link to="/scan">Scan</Link></li>
          <li><Link to="/about">About</Link></li>
        </ul>
      </div>
    </nav>
  );
};

export default Navbar;

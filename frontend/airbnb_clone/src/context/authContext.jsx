import React, { createContext, useState, useContext } from 'react';
import { logout } from '../services/apiRequests';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  
    const logoutUser = () => {
      logout()
      setUser(null);
    };
  

  return (
    <AuthContext.Provider value={{ user, setUser, logoutUser }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  return useContext(AuthContext);
};

import LogoIcon from "../../assets/logoicon/LogoIcon";
import { Button, Menu, MenuHandler, MenuItem, MenuList, Typography } from "@material-tailwind/react";
import  { useEffect, useRef, useState } from 'react';
import { Search } from "../search/Search";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faMagnifyingGlass } from "@fortawesome/free-solid-svg-icons";
import Forms from "../forms/Forms";
import { Link } from "react-router-dom";
import { useAuth } from "../../context/authContext";


export const NavBar = ({ hideSearch }) => {      
   

    const { user, logoutUser, isAdmin, isOwner } = useAuth()

    const [isSearchOpen, setIsSearchOpen] = useState(false);
        
    const [openLogin, setOpenLogin] = useState(false);
    const handleOpenLogin = () => setOpenLogin((cur) => !cur);

    const [openSignUp, setOpenSignUp] = useState(false);
    const handleOpenSignUp = () => setOpenSignUp((cur) => !cur);
    

    const openSearch = () => {
        setIsSearchOpen(!isSearchOpen);
    };

    const navRef = useRef(null);

    useEffect(() => {
        const handleClickOutside = (event) => {
        if (navRef.current && !navRef.current.contains(event.target)) {
            setIsSearchOpen(false);           
        }
        };

        document.addEventListener('mousedown', handleClickOutside);

        return () => {
        document.removeEventListener('mousedown', handleClickOutside);
        };
    }, []);   

   
    return ( 
            <> 
                <section className="py-3 px-8 flex justify-between items-center">        
                <Link to="/"><LogoIcon/></Link>
                    {!hideSearch && <div className="flex flex-col justify-center items-center -ml-8 mr-4" ref={navRef}>
                        <Button variant="outlined" onClick={openSearch} className="box-border flex items-center gap-2 rounded-3xl border border-gray-300 shadow-md hover:shadow-lg px-3 py-1">                              
                            <div className="flex items-center">
                                <h2 className="hidden md:inline mr-1">País de Destino | Huéspedes</h2>                               
                                <FontAwesomeIcon icon={faMagnifyingGlass} className="p-3 rounded-full m-0.5 bg-red-500 text-white text-sm" />                                
                            </div>                                                  
                        </Button>                    
                        {isSearchOpen && <Search />}
                    </div>}
                    <div className="flex flex-row gap-px md:gap-4"> 
                        {!user ? 
                        <div className="flex items-center gap-2">
                            <Button variant="text" className="rounded-full hidden sm:inline" onClick={handleOpenSignUp}>Registrarse</Button>
                            <Button variant="outlined" className="rounded-full" onClick={handleOpenLogin}>Iniciar Sesión</Button>
                        </div> 
                        :
                        <div className="flex items-center gap-2">
                            <Typography>
                                Bienvenido: {user ? user.firstname : ""}
                            </Typography>
                            <Menu>
                                <MenuHandler>
                                    <Button variant="outlined" className="rounded-full">Menu</Button>
                                </MenuHandler>
                                <MenuList>
                                    {isAdmin && <Link to="/admin-panel"><MenuItem>Panel Admin</MenuItem></Link>}
                                    {isOwner && <Link to="/property-register"><MenuItem>Registrar una Propiedad</MenuItem></Link>}
                                    <Link to="/account-settings"><MenuItem>Cuenta</MenuItem></Link>
                                    <Link to="/"><MenuItem onClick={() => logoutUser()}>Cerrar Sesión</MenuItem></Link>
                                </MenuList>
                            </Menu>
                        </div>}
                        <Forms
                            openLogin={openLogin}
                            openSignUp={openSignUp}
                            handleOpenLogin={handleOpenLogin}
                            handleOpenSignUp={handleOpenSignUp}
                        />

                    </div>                    
                </section>  
            </>
        
    );
};


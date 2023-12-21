import { useLocation } from "react-router-dom";
import {NavBar, NavBarFilters} from "../navbar";


export const Header = () => {
    const location = useLocation();
    const hideOnRoutes = [
        '/account-settings', 
        '/property-register', 
        '/admin-panel', 
        '/personal-info', 
        '/properties-form',
    ];
   

    const shouldHide = hideOnRoutes.includes(location.pathname);

    if (shouldHide) {
      return (
        <header className="sticky top-0 z-50 bg-white">
          <NavBar hideSearch={shouldHide}/>
        </header>
      );
    }

   
    return (
        <header className="sticky top-0 z-50 bg-white">
            <NavBar/>
            <NavBarFilters/>            
        </header>
    );
};


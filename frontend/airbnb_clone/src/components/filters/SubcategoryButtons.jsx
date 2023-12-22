import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Link } from "react-router-dom";


export const SubcategoryButtons = ({ icon, text }) => {    
    const getButtonClassName = "flex flex-col items-center hover:text-gray-900 border-b-4 border-b-white hover:border-b-gray-900 p-2";
            
    return (
        <Link to={`/filtered-properties/${text}`}><button className={getButtonClassName} >
            <FontAwesomeIcon icon={icon} className="h-6" />
            {text}
        </button>
        </Link>
    );
};

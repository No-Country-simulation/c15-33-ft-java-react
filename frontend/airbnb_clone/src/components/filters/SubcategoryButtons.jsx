import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";


export const SubcategoryButtons = ({ icon, text }) => {
    const getButtonClassName = "flex flex-col items-center hover:text-gray-900 border-b-4 border-b-white hover:border-b-gray-900 p-2";
    
    return (
        <button className={getButtonClassName}>
            <FontAwesomeIcon icon={icon} className="h-6" />
            {text}
        </button>
    );
};

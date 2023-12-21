import { Link } from "react-router-dom";
import { UserCardDashboard } from "../../cards";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { 
  faAddressCard,
  faHotel,
  // faSuitcase 
} from "@fortawesome/free-solid-svg-icons";

const ownerSections = [
    {
      id: 1,
      title: "Información personal",
      description: "Proporciona tus datos personales e indícanos cómo podemos ponernos en contacto contigo.",
      path: "/personal-info",
      icon: <FontAwesomeIcon icon={faAddressCard} />,
    },
    // {
    //   id: 2,
    //   title: "Reservas activas",
    //   description: "Aquí puedes ver todas tus reservas activas, junto con la información del alojamiento.",
    //   path: "/trips",
    //   icon: <FontAwesomeIcon icon={faSuitcase} />,
    // },
    {
      id: 3,
      title: "Información de las propiedades",
      description: "Proporciona los detalles de tus propiedades para que los viajeros puedan reservarla.",
      path: "/properties",
      icon: <FontAwesomeIcon icon={faHotel} />,
    },
  ];

  const userSections = [
    {
        id: 1,
      title: "Información personal",
      description: "Proporciona tus datos personales e indícanos cómo podemos ponernos en contacto contigo.",
      path: "/personal-info",
      icon: <FontAwesomeIcon icon={faAddressCard} />,
    },
    // {
    //   id: 2,
    //   title: "Reservas activas",
    //   description: "Aquí puedes ver todas tus reservas activas, junto con la información del alojamiento.",
    //   path: "/trips",
    //   icon: <FontAwesomeIcon icon={faSuitcase} />,
    // },
  ];

export const AccountSettings = () => {
  const isOwner = true;
  return (  
    <div
      className="
        mt-2
        max-w-[2520px]
        mx-auto
        xl:px-40 
        md:px-20
        sm:px-2
        px-4
        pb-4
      "
    >
        <div className="container mt-5 font-mono">
          <div className="text-2xl">Cuenta:
            {
              isOwner ? <span> Propietario</span> : <span> Huesped</span>
            }
          </div>
          <span className="text-lg">
              Nombre del usuario, usuario@gmail.com
          </span>
        </div>
        <div 
          className="
          pt-6
          grid 
          grid-cols-1 
          sm:grid-cols-1
          md:grid-cols-2
          xl:grid-cols-3
          gap-8
          "
        >
          {isOwner ? ownerSections.map((section) => (
            <Link key={section.id} to={section.path}>
              <UserCardDashboard section={section} />
            </Link>
          )) : 
          userSections.map((section) => (
            <Link key={section.id} to={section.path}>
              <UserCardDashboard section={section} />
            </Link>
          ))}
        </div>
    </div>
  )
}

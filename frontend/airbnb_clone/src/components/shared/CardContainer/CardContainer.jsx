import { Link } from "react-router-dom";
import { Container, EmptyState, HostCardItem } from "..";

const propertiesList = [
  {
    id: 1,
    description: "Casa moderna en el centro de la ciudad",
    image: "https://source.unsplash.com/random",
    value: 5000,
    country: "Estados Unidos",
    categories: ["Residencial", "Centro urbano"],
    subCategory: "Casa",
    bathroom: 3,
    bed: 4,
    bedroom: 3,
    services: ["Electricidad", "Agua", "Gas"],
    reservationDate:"11-12 de dic",
  },
  {
    id: 2,
    description: "Apartamento con terraza panorámica",
    image: "https://source.unsplash.com/random?q=hotel%20paris",
    value: 2500,
    country: "España",
    categories: ["Residencial", "Vistas panorámicas"],
    subCategory: "Apartamento",
    bathroom: 2,
    bed: 2,
    bedroom: 1,
    services: ["Internet", "Agua", "Seguridad"],
    reservationDate: "20-22 de dic",
  },
  {
    id: 3,
    description: "Terreno amplio para desarrollo",
    image: "https://source.unsplash.com/random?q=vuelo%20new%20york%20tokio",
    value: 10000,
    country: "Argentina",
    categories: ["Terreno", "Desarrollo"],
    subCategory: "Terreno",
    bathroom: 0,
    bed: 0,
    bedroom: 0,
    services: [],
    reservationDate: "23 de dic",
  },
  {
    id: 4,
    description: "Casa colonial con jardín exuberante",
    image: "https://source.unsplash.com/random?q=restaurante%20roma",
    value: 7000,
    country: "México",
    categories: ["Residencial", "Jardín"],
    subCategory: "Casa",
    bathroom: 4,
    bed: 5,
    bedroom: 4,
    services: ["Electricidad", "Agua", "Mantenimiento de jardín"],
    reservationDate: "26 de dic",
  },
  {
    id: 5,
    description: "Apartamento moderno en zona comercial",
    image: "https://source.unsplash.com/random?q=paseo%20helicóptero%20gran%20cañón",
    value: 350,
    country: "Italia",
    categories: ["Residencial", "Zona comercial"],
    subCategory: "Apartamento",
    bathroom: 2,
    bed: 3,
    bedroom: 2,
    services: ["Internet", "Agua", "Seguridad"],
    reservationDate: "27 de dic",
  },
  {
    id: 6,
    description: "Casa de playa con acceso privado",
    image: "https://source.unsplash.com/random?q=safari+africano",
    value: 800,
    country: "Brasil",
    categories: ["Residencial", "Playa"],
    subCategory: "Casa",
    bathroom: 3,
    bed: 4,
    bedroom: 3,
    services: ["Electricidad", "Agua", "Acceso privado a la playa"],
    reservationDate: "29 de dic",
  },
];

export const CardContainer = () => {

  if (propertiesList.length === 0) {
    return (
      <EmptyState
        title={"Alojamientos"}
        subtitle={"No hay ningún alojamiento publicado... ¡por ahora!"}
        showReset={true}
      />
    );
  }

  return (
    <Container>
      <div 
          className="
            pt-6
            grid 
            grid-cols-1 
            sm:grid-cols-2 
            md:grid-cols-3 
            lg:grid-cols-4
            xl:grid-cols-5
            2xl:grid-cols-6
            gap-8
          "
        >
          {propertiesList.map((propertie) => (
            <Link
              key={propertie.id}
              to={`/property-detail/${propertie.id}`}
              state={{
                description: propertie.description,
                country: propertie.country,
                value: propertie.value,
                image: propertie.image,

                bedroom: propertie.bedroom,
                bed: propertie.bed,
                bathroom: propertie.bathroom,

                // categories={propertie.categories}
                // subCategory={propertie.subCategory}
                // services={propertie.services}
              }}
            >
              <HostCardItem
                description={propertie.description}
                country={propertie.country}
                reservationDate={propertie.reservationDate}
                value={propertie.value}
                image={propertie.image}
              />
            </Link>
          )
          )}
        </div>
    </Container>
  )
}
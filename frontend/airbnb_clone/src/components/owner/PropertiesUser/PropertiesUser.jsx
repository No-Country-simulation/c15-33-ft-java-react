import { useState } from "react";
import { Heading, PropertieCard } from "../../cards";
import { Container } from "../../shared";

// title
// description
// images
// value
// country
// categories
// subCategory
// detalles:
//  bathroom
//  bed
//  bedroom
// services

// title
// description
// images
// value
// location
// category
// subCategory
// bathroom
// bed
// bedroom
// serviceTypes
// permanent_availability
// availability
// active
// user

// const categories = [
//   {
//       name: "Departamento",
//       value: "apartment"
//   },
//   {
//       name: "Casa",
//       value: "house"
//   },
//   {
//       name: "Casa Huéspedes",
//       value: "guest_house"
//   },
//   {
//       name: "Hotel",
//       value: "hotel"
//   }
// ];

// const subcategories = [
//   {
//       name: "Playa",
//       value: "beach"
//   },
//   {
//       name: "Lago",
//       value: "lake"
//   },
//   {
//       name: "Montaña",
//       value: "mountain"
//   },
//   {
//       name: "Campo",
//       value: "countryside"
//   },
//   {
//       name: "Pileta",
//       value: "swimming_pool"
//   },
//   {
//       name: "Urbana",
//       value: "urban"
//   },
//   {
//       name: "Tropical",
//       value: "tropical"
//   },
//   {
//       name: "Cabaña",
//       value: "cabin"
//   },
//   {
//       name: "Camping",
//       value: "camping"
//   }
// ];

// const quantity = ["1", "2", "3", "4", "5", "6+"];

// const services = [
//     {text: "Wi-Fi", value: "wifi" },
//     {text: "Cocina", value: "kitchen" },
//     {text: "Lavarropas", value: "washing_machine" },
//     {text: "Aire Acondicionado", value: "air_conditioner" },
//     {text: "Calefacción", value: "heating" },
//     {text: "Pileta", value: "swimming_pool" },
//     {text: "Estacionamiento", value: "parking_lot" },
//     {text: "Cuna", value: "cradle" },
//     {text: "Parilla", value: "grill" },
//     {text: "Desayuno", value: "breakfast" },
//     {text: "Se puede fumar", value: "smoking_allowed" },
//     {text: "Permite mascotas", value: "pets_allowed" },
//     {text: "Cancelación anticipada", value: "early_cancellation"}
// ];

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
  },
  {
    id: 5,
    description: "Apartamento moderno en zona comercial",
    image: "https://source.unsplash.com/random?q=paseo%20helicóptero%20gran%20cañón",
    value: 3500,
    country: "Italia",
    categories: ["Residencial", "Zona comercial"],
    subCategory: "Apartamento",
    bathroom: 2,
    bed: 3,
    bedroom: 2,
    services: ["Internet", "Agua", "Seguridad"],
  },
  {
    id: 6,
    description: "Casa de playa con acceso privado",
    image: "https://source.unsplash.com/random?q=safari+africano",
    value: 8000,
    country: "Brasil",
    categories: ["Residencial", "Playa"],
    subCategory: "Casa",
    bathroom: 3,
    bed: 4,
    bedroom: 3,
    services: ["Electricidad", "Agua", "Acceso privado a la playa"],
  },
];

export const PropertiesUser = () => {

  const [properties, setProperties] = useState(propertiesList);

  const handleCancel = (id) => {
    // Filtrar la lista para eliminar la reserva con el ID dado
    const updatedProperties = properties.filter((propertie) => propertie.id !== id);
    setProperties(updatedProperties);
  };

  return (
    <Container>
      <Heading
        title="Propiedades"
        subtitle="Lista de tus propiedades"
      />
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
        {
          properties.map((propertie) => (
            <PropertieCard
              key={propertie.id}
              handleCancel={handleCancel}
              id={propertie.id}
              description={propertie.description}
              image={propertie.image}
              value={propertie.value}
              country={propertie.country}
              categories={propertie.categories}
              subCategory={propertie.subCategory}
              bathroom={propertie.bathroom}
              bed={propertie.bed}
              bedroom={propertie.bedroom}
              services={propertie.services}
            />
          ))
        }
      </div>
    </Container>
  )
}

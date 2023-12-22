import { useState } from "react";
import { Heading, PropertieCard } from "../../cards";
import { Container } from "../../shared";

// title
// description
// images
// value
// location: country
// category
// subCategory
// bathroom
// bed
// bedroom
// serviceTypes
// active

// title: null,
// description: null,
// images: [],
// value: null,
// location: null,
// category: null,
// subCategory: null,
// bathroom: null,
// bed: null,
// bedroom: null,
// serviceTypes: [],
// active: 'true',

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

// title
// description
// images
// value
// location: country
// category
// subCategory
// bathroom
// bed
// bedroom
// serviceTypes
// active

const propertiesList = [
  {
    id: 1,
    title: "Casa moderna en el centro de la ciudad",
    description: "Descubre la sofisticación urbana en esta casa moderna situada en el centro de la ciudad. Con un diseño vanguardista y amplias ventanas que llenan de luz cada rincón, esta residencia ofrece una combinación perfecta de estilo y comodidad. La sala de estar y la cocina gourmet exhiben un elegante equilibrio entre funcionalidad y estética, mientras que los dormitorios cuentan con lujosos baños en suite.",
    images: "https://source.unsplash.com/random",
    value: 5000,
    location: "Estados Unidos",
    category: ["Residencial", "Centro urbano"],
    subCategory: "Casa",
    bathroom: 3,
    bed: 4,
    bedroom: 3,
    serviceTypes: ["Electricidad", "Agua", "Gas"],
    active: true
  },
  {
    id: 2,
    title: "Apartamento con terraza panorámica",
    description: "Sumérgete en la elegancia de este encantador apartamento con terraza panorámica. Con una vista impresionante que abarca la ciudad, esta residencia redefine la experiencia urbana. El interior presenta un diseño moderno y funcional, con espacios luminosos que se abren hacia la terraza, creando una fusión perfecta entre el interior y el exterior. La cocina bien equipada y las áreas de estar proporcionan un ambiente acogedor, mientras que la terraza se convierte en un oasis privado para disfrutar de atardeceres inolvidables.",
    images: "https://source.unsplash.com/random?q=hotel%20paris",
    value: 2500,
    location: "España",
    category: ["Residencial", "Vistas panorámicas"],
    subCategory: "Apartamento",
    bathroom: 2,
    bed: 2,
    bedroom: 1,
    serviceTypes: ["Internet", "Agua", "Seguridad"],
    active: true
  },
  {
    id: 3,
    title: "Terreno amplio para desarrollo",
    description: "Descubre el potencial ilimitado de este extenso terreno destinado al desarrollo. Con amplitud de espacio para materializar tus visiones arquitectónicas, este terreno ofrece oportunidades excepcionales para proyectos ambiciosos. Su ubicación estratégica y generosas dimensiones proporcionan la base perfecta para la creación de un espacio único y vibrante. Aprovecha esta oferta para dar vida a tu visión de desarrollo en este terreno expansivo que promete posibilidades sin límites.",
    images: "https://source.unsplash.com/random?q=vuelo%20new%20york%20tokio",
    value: 10000,
    location: "Argentina",
    category: ["Terreno", "Desarrollo"],
    subCategory: "Terreno",
    bathroom: 1,
    bed: 1,
    bedroom: 1,
    serviceTypes: ["Agua", "Seguridad"],
    active: true
  },
  {
    id: 4,
    title: "Casa colonial con jardín exuberante",
    description: "Sumérgete en la elegancia atemporal de esta encantadora casa colonial con un jardín exuberante. Con su arquitectura clásica y encanto histórico, esta residencia ofrece un refugio sereno en medio de la ciudad. El jardín, meticulosamente cuidado, brinda un oasis de verdor y tranquilidad, creando un espacio perfecto para la relajación al aire libre.",
    images: "https://source.unsplash.com/random?q=restaurante%20roma",
    value: 7000,
    location: "México",
    category: ["Residencial", "Jardín"],
    subCategory: "Casa",
    bathroom: 4,
    bed: 5,
    bedroom: 4,
    serviceTypes: ["Electricidad", "Agua", "Mantenimiento de jardín"],
    active: true
  },
  {
    id: 5,
    title: "Apartamento moderno en zona comercial",
    description: "Experimenta la vida contemporánea con este apartamento moderno ubicado en plena zona comercial. Con un diseño vanguardista y acabados de alta calidad, esta residencia redefine la comodidad y el estilo en el corazón de la actividad comercial. Sus amplias ventanas permiten una abundancia de luz natural, destacando los espacios interiores meticulosamente diseñados.",
    images: "https://source.unsplash.com/random?q=paseo%20helicóptero%20gran%20cañón",
    value: 3500,
    location: "Italia",
    category: ["Residencial", "Zona comercial"],
    subCategory: "Apartamento",
    bathroom: 2,
    bed: 3,
    bedroom: 2,
    serviceTypes: ["Internet", "Agua", "Seguridad"],
    active: true
  },
  {
    id: 6,
    title: "Casa de playa con acceso privado",
    description: "Sumérgete en la serenidad costera con esta encantadora casa de playa que ofrece acceso privado a la arena y las olas. Diseñada para capturar la esencia relajada del estilo de vida junto al mar, esta residencia cuenta con amplios espacios abiertos y una decoración luminosa que se fusiona perfectamente con el entorno natural. Disfruta de vistas panorámicas al océano desde la comodidad de tu hogar y accede directamente a la playa desde tu propio paraíso privado.",
    images: "https://source.unsplash.com/random?q=safari+africano",
    value: 8000,
    location: "Brasil",
    category: ["Residencial", "Playa"],
    subCategory: "Casa",
    bathroom: 3,
    bed: 4,
    bedroom: 3,
    serviceTypes: ["Electricidad", "Agua", "Acceso privado a la playa"],
    active: true
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
              title={propertie.title}
              description={propertie.description}
              images={propertie.images}
              value={propertie.value}
              location={propertie.location}
              category={propertie.category}
              subCategory={propertie.subCategory}
              bathroom={propertie.bathroom}
              bed={propertie.bed}
              bedroom={propertie.bedroom}
              serviceTypes={propertie.serviceTypes}
              active={propertie.active}
            />
          ))
        }
      </div>
    </Container>
  )
}

import { Button } from "@material-tailwind/react";
import { Link } from "react-router-dom";

export const PropertieCard = ({
  title,
  location,
  category,
  subCategory,
  bathroom,
  bed,
  bedroom,
  serviceTypes,
  active,
  description,
  value,
  images,
  handleCancel,
  id
}) => {
  return (
    <div
        className="col-span-1 cursor-pointer group"
      >
        <div className="flex flex-col gap-4 w-full">
          <Link to={"/properties-form"} state={{
            title,
            location,
            category,
            subCategory,
            bathroom,
            bed,
            bedroom,
            serviceTypes,
            active,
            description,
            value,
            images,
            id
          }}>
            <div 
              className="
                aspect-square 
                w-full 
                relative 
                overflow-hidden 
                rounded-xl
              "
            >
              <img
                src={images}
                alt="image 2"
                className="object-cover 
                  h-full 
                  w-full 
                  group-hover:scale-110 
                  transition"
              />

              <div className="
                absolute
                top-3
                right-3
              ">
              </div>
            </div>
          
          <div className="font-semibold mt-2 xl:text-sm md:text-base sm:text-lg truncate">
            {description}
          </div>

          <div className="font-light mt-2 text-gray-700 xl:text-sm md:text-base sm:text-lg truncate">
            {location}
          </div>

          <div className="font-semibold mt-2 xl:text-sm md:text-base sm:text-lg truncate">
            ${value} por noche
          </div>
          </Link>

          <Button onClick={() => handleCancel(id)} color="pink" variant="gradient" type="submit">Eliminar</Button>
        </div>
    </div>
  )
}

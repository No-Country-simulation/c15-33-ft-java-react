import { Button } from "@material-tailwind/react";
import { Link } from "react-router-dom";

export const PropertieCard = ({description, country, value, image, handleCancel, id}) => {
  // categories
  // subCategory
  // bathroom
  // bed
  // bedroom
  // services
  return (
    <div
        className="col-span-1 cursor-pointer group"
      >
        <div className="flex flex-col gap-2 w-full">
          <Link to={"/properties-form"} state={{description, country, value, image, id}}>
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
                src={image}
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
          
          <div className="font-semibold xl:text-sm md:text-base sm:text-lg truncate">
            {description}
          </div>

          <div className="font-light text-gray-700 xl:text-sm md:text-base sm:text-lg truncate">
            {country}
          </div>

          <div className="font-semibold xl:text-sm md:text-base sm:text-lg truncate">
            ${value} por noche
          </div>
          </Link>

          <Button onClick={() => handleCancel(id)} color="pink" variant="gradient" type="submit">Eliminar</Button>
        </div>
    </div>
  )
}

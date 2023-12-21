import { Button } from "@material-tailwind/react";

export const ReservationCard = ({location, address, price, image, handleCancel, id}) => {
  return (
    <div
        className="col-span-1 cursor-pointer group"
      >
        <div className="flex flex-col gap-2 w-full">
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
            {location}
          </div>

          <div className="font-light text-gray-700 xl:text-sm md:text-base sm:text-lg truncate">
            {address}
          </div>

          <div className="font-semibold xl:text-sm md:text-base sm:text-lg truncate">
            ${price} por noche
          </div>
          
          <Button onClick={() => handleCancel(id)} color="pink" variant="gradient" type="submit">Cancelar</Button>
        </div>
    </div>
  )
}
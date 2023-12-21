import { Button } from "@material-tailwind/react";
import { Heading } from "../../cards";
import { Link } from "react-router-dom";

export const EmptyState = ({
    title = "Reservas",
    subtitle = "No tenes ningún viaje reservado... ¡por ahora!",
    showReset = true
  }) => {
  return (
    <div 
      className="
        mt-6
        flex 
        flex-col 
        gap-2 
        justify-center 
        items-center 
      "
    >
      <Heading
        center
        title={title}
        subtitle={subtitle}
      />
      <div className="w-48 mt-4">
        {showReset && (
            <Link to='/'>
                <div className="flex justify-center mt-4">
                    <Button variant="outlined" type="submit">Empieza a buscar</Button>
                </div>
            </Link>
        )}
      </div>
    </div>
  )
}

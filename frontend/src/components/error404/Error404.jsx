import {
  Card,
  CardHeader,
  CardBody,
  CardFooter,
  Typography,
  Button,
} from "@material-tailwind/react";
import { Link } from "react-router-dom";

const Error404 = () => {
  return (
    <>      
      <div className="box-border w-full h-11/12 flex flex-col gap-8 items-center justify-center p-12 pt-28 md:p-32">              
        <Card className="flex items-center justify-center">
          <CardHeader color="blue-gray" floated={false}>
            <img
              src="https://midu.dev/images/this-is-fine-404.gif"
              alt="imagen de error 404, página no encontrada"
            />
          </CardHeader>
          <CardBody>
            <Typography variant="h5" color="blue-gray" className="mb-2">
              Error code: 404 - Página no encontrada
            </Typography>
            <Typography>
              Algo salió mal...La página solicitada no fue encontrada.
            </Typography>
          </CardBody>
          <CardFooter className="pt-0">
            <Button color="red"><Link to="/">Volver a Inicio</Link></Button>
          </CardFooter>
        </Card>  
      </div>      
    </>    
  );     
};

export default Error404;
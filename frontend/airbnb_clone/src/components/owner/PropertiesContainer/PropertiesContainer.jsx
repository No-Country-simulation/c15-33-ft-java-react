import { EmptyState } from "../../shared";
import { PropertiesUser } from "../";

export const PropertiesContainer = () => {
  const reservations = [{prueba : 1}, {prueba :2}];

  if (reservations.length === 0) {
    return (
      <EmptyState
        title={"Propiedades"}
        subtitle={"No tenes ningúna propiedad publicada... ¡por ahora!"}
        showReset={true}
      />
    );
  }

  return (
    <PropertiesUser />
  );
}
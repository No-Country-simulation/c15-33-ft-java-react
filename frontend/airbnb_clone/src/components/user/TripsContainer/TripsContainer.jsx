import { EmptyState } from "../../shared";
import { TripsUser } from "../TripsUser";

export const TripsContainer = () => {
    const reservations = [{prueba : 1}, {prueba :2}];

  if (reservations.length === 0) {
    return (
      <EmptyState />
    );
  }

  return (
    <TripsUser />
  );
}

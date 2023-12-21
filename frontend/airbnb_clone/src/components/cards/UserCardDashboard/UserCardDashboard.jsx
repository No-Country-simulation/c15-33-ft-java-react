import { Card, CardBody, Typography} from "@material-tailwind/react";

export const UserCardDashboard = ({section}) => {
  return (
    <Card key={section.id} className="mt-6 w-96">
      <CardBody>
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="currentColor"
            className="mb-4 h-12 w-12 text-gray-900"
            >
            {section.icon}
          </svg>

          <Typography variant="h5" color="blue-gray" className="mb-2">
              {section.title}
          </Typography>

          <Typography>
              {section.description}
          </Typography>
      </CardBody>
    </Card>
  )
}
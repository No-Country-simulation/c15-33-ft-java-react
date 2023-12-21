import { createBrowserRouter, RouterProvider } from "react-router-dom";
import Root from "../components/root/Root";
import { Error404 } from "../components/error404/Error404";
import { CardContainer } from "../components/shared";
import { PropertyRegister } from "../components/property/PropertyRegister";
import { DetailContainerCard } from "../components/cards";
import { AccountSettings, PersonalInfoForm, TripsContainer } from "../components/user";
import { AdminPanel } from "../components/admin/AdminPanel";
import { Test } from "../components/Test";
import { PropertiesContainer } from "../components";
import { PropertiesUpdateForm } from "../components/owner";

const router = createBrowserRouter([
    {
        path: "/",
        element: <Root/>,
        errorElement: <Error404/>,
        children: [
            {
                path: "/",
                element: <CardContainer/>,
            },
            {
                path: "/property-register",
                element: <PropertyRegister/>
            },
            {
                path: "/property-detail/:id",
                element: <DetailContainerCard />
            },
            {
                path: "/account-settings",
                element: <AccountSettings />
            },
            {
                path: "/admin-panel",
                element: <AdminPanel/>
            },
            {
                path: "/personal-info",
                element: <PersonalInfoForm />
            },
            {
                path: "/test",
                element: <Test/>
            },
            {
                path: "/trips",
                element: <TripsContainer />
            },
            {
                path: "/properties",
                element: <PropertiesContainer />
            },
            {
                path: "/properties-form",
                element: <PropertiesUpdateForm />
            }
        ],
    },
]);

export const Router = () => {
    return <RouterProvider router={router} />;
};

package com.clonair.back.user;

import java.util.List;

public record UserResponse(
        String id,
        String username,
        String firstname,
        String lastname,
        String country,
        Role role,
        List<String> propertyIds, // Lista de IDs de propiedades relacionadas
        String contact,
        String description
) {}

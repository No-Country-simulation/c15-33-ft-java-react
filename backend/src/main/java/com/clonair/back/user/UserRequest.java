package com.clonair.back.user;

public record UserRequest(
    String firstname,
    String lastname,
    String country,
    String contact,
    String description
){}

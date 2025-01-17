package com.nadhem.produits.restcontrollers;


import com.nadhem.produits.entities.Categorie;
import com.nadhem.produits.repos.CategorieRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/cat") @CrossOrigin("*")
public class CategorieRESTController {
    @Autowired
    CategorieRepository categorieRepository;
    @RequestMapping (method= RequestMethod.GET) public List<Categorie> getAllCategories()
    {
        return categorieRepository.findAll();
    }
}

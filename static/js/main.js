/*====================================================
        PART 2C-3B-2B-2A
        ANIMATIONS
====================================================*/

/*==========================================
        FADE-IN ANIMATION
==========================================*/

const fadeElements = document.querySelectorAll(
    "section, .card, img"
);

const observer = new IntersectionObserver(

(entries)=>{

    entries.forEach((entry)=>{

        if(entry.isIntersecting){

            entry.target.classList.add("show");

        }

    });

},

{
    threshold:0.15
}

);

fadeElements.forEach((element)=>{

    element.classList.add("hidden");

    observer.observe(element);

});


/*==========================================
        HERO IMAGE ANIMATION
==========================================*/

const heroImage=document.querySelector(".hero-image");

if(heroImage){

    heroImage.animate(

    [

        {
            transform:"translateY(0px)"
        },

        {
            transform:"translateY(-12px)"
        },

        {
            transform:"translateY(0px)"
        }

    ],

    {

        duration:2500,

        iterations:Infinity

    }

    );

}


/*==========================================
        CARD HOVER EFFECT
==========================================*/

const cards=document.querySelectorAll(".card");

cards.forEach((card)=>{

    card.addEventListener("mouseenter",()=>{

        card.style.transform="translateY(-10px) scale(1.02)";

    });

    card.addEventListener("mouseleave",()=>{

        card.style.transform="translateY(0px) scale(1)";

    });

});


/*==========================================
        IMAGE HOVER EFFECT
==========================================*/

const images=document.querySelectorAll("img");

images.forEach((img)=>{

    img.addEventListener("mouseenter",()=>{

        img.style.transition=".4s";

        img.style.transform="scale(1.03)";

    });

    img.addEventListener("mouseleave",()=>{

        img.style.transform="scale(1)";

    });

});


/*==========================================
        SECTION TITLE EFFECT
==========================================*/

const titles=document.querySelectorAll("h2");

titles.forEach((title)=>{

    title.addEventListener("mouseenter",()=>{

        title.style.color="#38bdf8";

    });

    title.addEventListener("mouseleave",()=>{

        title.style.color="";

    });

});


console.log("Animations Loaded Successfully");
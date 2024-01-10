<?php

function getImage($filename) {

    $imagePath = '../uploads/' . $filename;
    
    $imageData = file_get_contents($imagePath);
    
    $extension = pathinfo($imagePath, PATHINFO_EXTENSION);
    $contentType = 'image/' . $extension;
    header('Content-Type: ' . $contentType);
    
    echo $imageData;
    
}

?>
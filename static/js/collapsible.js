document.addEventListener("DOMContentLoaded", function () {
    console.log("Collapsible folder script loaded");

    const folderContainers = document.querySelectorAll(".folder-container");
    console.log(`Found ${folderContainers.length} folder containers`);

    folderContainers.forEach(folder => {
        console.log("Processing folder:", folder);

        // Create a collapse/expand button dynamically
        const collapseButton = document.createElement("span");
        collapseButton.textContent = "-"; // Default state is expanded
        collapseButton.className = "collapse-btn";
        collapseButton.style.cursor = "pointer";
        collapseButton.style.marginLeft = "10px"; // Position the button to the right of the folder name

        // Add the collapse button after the folder name
        const folderName = folder.querySelector(".folder-name");
        if (!folderName) {
            console.warn("No folder name found in:", folder);
            return; // Skip if there's no folder name
        }
        folderName.append(collapseButton);

        // Get the elements to toggle: files and subfolders
        const filesList = folder.nextElementSibling?.tagName === "UL" ? folder.nextElementSibling : null; // Check if next sibling is a UL
        const subfolderContainer = folder.querySelector(".subfolder-container");

        console.log("Files list:", filesList);
        console.log("Subfolder container:", subfolderContainer);

        // Toggle visibility on collapse button click
        collapseButton.addEventListener("click", function () {
            console.log(`Collapse button clicked for folder: ${folderName.textContent.trim()}`);

            const isCollapsed = collapseButton.textContent === "+";

            // Toggle files and subfolders
            if (filesList) {
                filesList.style.display = isCollapsed ? "block" : "none";
                console.log(`Files list ${isCollapsed ? "shown" : "hidden"} for folder: ${folderName.textContent.trim()}`);
            }
            if (subfolderContainer) {
                subfolderContainer.style.display = isCollapsed ? "block" : "none";
                console.log(`Subfolder container ${isCollapsed ? "shown" : "hidden"} for folder: ${folderName.textContent.trim()}`);
            }

            // Update the button symbol
            collapseButton.textContent = isCollapsed ? "-" : "+";
            console.log(`Collapse button updated to: ${collapseButton.textContent} for folder: ${folderName.textContent.trim()}`);
        });

        // Add collapsible buttons for subfolders if any exist
        if (subfolderContainer) {
            const subfolderItems = subfolderContainer.querySelectorAll(".subfolder-item");
            console.log(`Found ${subfolderItems.length} subfolder items in folder: ${folderName.textContent.trim()}`);
            subfolderItems.forEach(subfolder => {
                addCollapseButton(subfolder);
            });
        }
    });

    function addCollapseButton(subfolder) {
        console.log("Processing subfolder:", subfolder);

        // Create collapse button for subfolders
        const collapseButton = document.createElement("span");
        collapseButton.textContent = "-"; // Default state is expanded
        collapseButton.className = "collapse-btn";
        collapseButton.style.cursor = "pointer";
        collapseButton.style.marginLeft = "10px"; // Position the button to the right of the subfolder name

        const subfolderName = subfolder.querySelector(".subfolder-name");
        if (!subfolderName) {
            console.warn("No subfolder name found in:", subfolder);
            return; // Skip if there's no subfolder name
        }
        subfolderName.append(collapseButton);

        // Get elements to toggle for the subfolder
        const subSubfolderContainer = subfolder.querySelector(".subsubfolder-container");
        const filesList = subfolder.nextElementSibling?.tagName === "UL" ? subfolder.nextElementSibling : null;

        collapseButton.addEventListener("click", function () {
            console.log(`Collapse button clicked for subfolder: ${subfolderName.textContent.trim()}`);

            const isCollapsed = collapseButton.textContent === "+";

            if (filesList) {
                filesList.style.display = isCollapsed ? "block" : "none";
                console.log(`Files list ${isCollapsed ? "shown" : "hidden"} for subfolder: ${subfolderName.textContent.trim()}`);
            }
            if (subSubfolderContainer) {
                subSubfolderContainer.style.display = isCollapsed ? "block" : "none";
                console.log(`Subsubfolder container ${isCollapsed ? "shown" : "hidden"} for subfolder: ${subfolderName.textContent.trim()}`);
            }

            collapseButton.textContent = isCollapsed ? "-" : "+";
        });

        // Recursively add buttons for sub-subfolders
        if (subSubfolderContainer) {
            const subSubfolderItems = subSubfolderContainer.querySelectorAll(".subsubfolder-item");
            console.log(`Found ${subSubfolderItems.length} subsubfolder items in subfolder: ${subfolderName.textContent.trim()}`);
            subSubfolderItems.forEach(subSubfolder => {
                addCollapseButton(subSubfolder);
            });
        }
    }
});

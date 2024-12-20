console.log("JavaScript filter yurh Loaded");  // Check if JS is running
console.log("Filter function loaded"); // Confirm JS is loaded

document.addEventListener("DOMContentLoaded", function () {
    const departmentFilterDropdown = document.querySelector("select[name='department_filter']");
    const folderContainers = document.querySelectorAll(".folder-container");

    // Initialize departmentFilter based on URL or default value
    let departmentFilter = departmentFilterDropdown?.value || "";

    // Event listener for dropdown change
    if (departmentFilterDropdown) {
        departmentFilterDropdown.addEventListener("change", function () {
            departmentFilter = this.value; // Get selected department
            applyDepartmentFilter(departmentFilter);
        });
    }

    // Function to apply department filtering
    function applyDepartmentFilter(filterValue) {
        console.log("Applying department filter:", filterValue); // Log the filter value

        folderContainers.forEach(folder => {
            const folderDepartmentId = folder.getAttribute("data-department-id"); // Get department ID from folder
            if (filterValue === "" || folderDepartmentId === filterValue) {
                folder.style.display = ""; // Show matching folders
            } else {
                folder.style.display = "none"; // Hide non-matching folders
            }
        });
    }

    // Apply filter on page load (if any filter is preselected)
    applyDepartmentFilter(departmentFilter);
});

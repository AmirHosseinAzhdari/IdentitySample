using System.Collections.Generic;
using IdentitySample.ViewModel.Role;

namespace IdentitySample.Repositories
{
    public interface IUtilities
    {
        public IList<ActionAndControllerName> AreaAndActionAndControllerNamesList();

        public IList<string> GetAllAreasNames();

        public string DataBaseRoleValidationGuid();
    }
}
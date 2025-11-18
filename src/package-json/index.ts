export {
  findPackageJsonFiles,
  detectWorkspaces,
  type WorkspaceConfig,
  type PackageJsonLocation,
} from './find.js'

export {
  isPostinstallConfigured,
  generateUpdatedPostinstall,
  updatePackageJsonObject,
  updatePackageJsonContent,
  type PostinstallStatus,
} from './detect.js'

export {
  updatePackageJson,
  updateMultiplePackageJsons,
  type UpdateResult,
} from './update.js'

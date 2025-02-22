/**
 * Mask generation functions.
 *
 * @author Stefan Siegl
 * @author Chris Breuer
 */

import { md } from './md'

export const mgf = {
  mgf1: md.sha1.create().update('sha1').digest(),
}
